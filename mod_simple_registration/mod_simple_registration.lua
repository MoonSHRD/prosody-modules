prosody.unlock_globals()
require "ltn12";
prosody.lock_globals()

local st = require "util.stanza";
local usermanager = require "core.usermanager";
local dataform_new = require "util.dataforms".new;
local nodeprep = require "util.encodings".stringprep.nodeprep;
local uuid = require "util.uuid";
local id = require "util.id";
local smtp = require "socket.smtp";
local timer = require "util.timer";
--local socket = require "socket";
--local ssl = require "ssl";

local require_email = module:get_option_boolean("reg_require_email", false);
local require_encryption = module:get_option_boolean("c2s_require_encryption",
    module:get_option_boolean("require_encryption", false));
local user_profiles = module:open_store("user_profiles", "keyval") -- stores data about users (user_id -> table)
local usernames = module:open_store("usernames", "keyval") -- stores data about usernames (username -> user_id)
local emails = module:open_store("user_emails", "keyval") -- stores data about existing user emails (email -> user_id)

local register_stream_feature = st.stanza("register", {xmlns="http://moonshard.tech/features/iq-register"}):up();
module:hook("stream-features", function(event)
	local session, features = event.origin, event.features;

	-- Advertise registration to unauthorized clients only.
	if session.type ~= "c2s_unauthed" or (require_encryption and not session.secure) then
		return
	end

	features:add_child(register_stream_feature);
end);

local smtp_server = module:get_option_string("smtp_server", "localhost");
local smtp_port = module:get_option_string("smtp_port", "25");
local smtp_ssl = module:get_option_boolean("smtp_ssl", false);
local smtp_user = module:get_option_string("smtp_username");
local smtp_pass = module:get_option_string("smtp_password");
local smtp_address = module:get_option("smtp_from") or ((smtp_user or "noreply").."@"..(smtp_server or module.host));
local mail_subject_prefix = module:get_option_string("email_subject_prefix")

local pending_registrations = {};
local pending_usernames = {};
local pending_emails = {};
local pending_validation_codes = {};

local field_map = {
	FORM_TYPE = { name = "FORM_TYPE", type = "hidden", value = "moonshard:iq:register" };
	username = { name = "username", type = "text-single", label = "Username", required = true };
	password = { name = "password", type = "text-private", label = "Password", required = true };
	email = { name = "email", type = "text-single", label = "Email" };
};

local registration_form = dataform_new {
	field_map.FORM_TYPE;
	field_map.username;
	field_map.password;
	field_map.email;
};

local registration_query = st.stanza("query", {xmlns = "moonshard:iq:register"})
	:tag(field_map.username.name):up()
	:tag(field_map.password.name):up();


if require_email then
	registration_query:tag(field_map.email.name):up();
	field_map.email.requred = true;
end

local function parse_data_forms(query)
	local form = query:get_child("x", "jabber:x:data");
	if form then
		return registration_form:data(form);
	else
		local data = {};
		local errors = {};
		for _, field in ipairs(registration_form) do
			local name, required = field.name, field.required;
			if field_map[name] then
				data[name] = query:get_child_text(name);
				if (not data[name] or #data[name] == 0) and required then
					errors[name] = "Required value missing";
				end
			end
		end
		if next(errors) then
			return data, errors;
		end
		return data;
	end
end

local function username_exists(username)
	if usernames:get(username) then return true else return false end;
end

local function email_exists(email)
	if emails:get(email) then return true else return false end;
end

function template(data)
	return { apply = function(values) return (data:gsub("{([^}]+)}", values)); end }
end


local function get_template(name, extension)
	local fh = assert(module:load_resource("templates/"..name..extension));
	local data = assert(fh:read("*a"));
	fh:close();
	return template(data);
end


local function render_template(template, data)
	return tostring(template.apply(data));
end

--[[ function enable_ssl()
    local sock = socket.tcp()
    return setmetatable({
    	 connect = function(_, host, port)
            local r, e = sock:connect(host, port)
            if not r then return r, e end
            sock = ssl.wrap(sock, {mode='client', protocol='tlsv1'})
            return sock:dohandshake()
        end
    }, {
        __index = function(t,n)
            return function(_, ...)
                return sock[n](sock, ...)
            end
        end
    })
end -- ]]

function send_email(address, message_text, subject)
	local rcpt = "<"..address..">";

	local mesgt = {
		headers = {
			to = address;
			subject = subject;
		};
		body = message_text;
	};

	local ok, err = nil;

	if not smtp_ssl then
		ok, err = smtp.send{ from = smtp_address, rcpt = rcpt, source = smtp.message(mesgt),
				server = smtp_server, user = smtp_user, password = smtp_pass, port = smtp_port };
	end
	-- [[ else
		--[[ok, err = smtp.send{ from = smtp_address, rcpt = rcpt, source = smtp.message(mesgt),
                server = smtp_server, user = smtp_user, password = smtp_pass, port = smtp_port, create = enable_ssl };
	end -- ]] -- //FIXME temporary disable ssl

	if not ok then
		module:log("error", "Failed to deliver to %s: %s", tostring(address), tostring(err));
		return;
	end
	return true;
end

module:hook("stanza/iq/moonshard:iq:register:query", function(event)
	local session, stanza = event.origin, event.stanza;
	local log = session.log or module._log;

	if session.type ~= "c2s_unauthed" then
		log("debug", "Attempted registration when disabled or already authenticated");
		session.send(st.error_reply(stanza, "cancel", "service-unavailable"));
		return true;
	end

	if require_encryption and not session.secure then
		session.send(st.error_reply(stanza, "modify", "policy-violation", "Encryption is required"));
		return true;
	end

	local query = stanza.tags[1];
	if stanza.attr.type == "get" then
		local reply = st.reply(stanza);
		reply:add_child(registration_query);
		session.send(reply);
		return true;
	end

	local dataform, errors = parse_data_forms(query);
	if errors then
		log("debug", "Error parsing registration form:");
		local textual_errors = {};
		for field, err in pairs(errors) do
			log("debug", "Field %q: %s", field, err);
			table.insert(textual_errors, ("%s: %s"):format(field:gsub("^%a", string.upper), err));
		end
		session.send(st.error_reply(stanza, "modify", "not-acceptable", table.concat(textual_errors, "\n")));
		return true;
	end

	local username, password = nodeprep(dataform.username), dataform.password;
	dataform.username, dataform.password = nil, nil;
	local host = module.host;
	if not username or username == "" then
		log("debug", "The requested username is invalid.");
		session.send(st.error_reply(stanza, "modify", "not-acceptable", "The requested username is invalid."));
		return true;
	end

	local user_id = uuid.generate()
	if usermanager.user_exists(user_id, host) then
		log("debug", "Attempt to register with existing user id");
		session.send(st.error_reply(stanza, "cancel", "conflict", "The user id already exists."));
		return true;
	end

	local user = {
		user_id = user_id,
		username = username,
		password = password,
		host = host
	}

	if username_exists(user.username) then
		log("debug", "Attempt to register with existing username");
		session.send(st.error_reply(stanza, "cancel", "conflict", "The requested username already exists."));
		return true;
	end

	if pending_usernames[user.username] then
		log("debug", "Attempt to register with pending username");
		session.send(st.error_reply(stanza, "cancel", "conflict", "The requested username is registering."));
		return true;
	end

	if require_email then
		user.email = dataform.email;
		if email_exists(user.email) then
			log("debug", "Attempt to register with existing email");
			session.send(st.error_reply(stanza, "cancel", "conflict", "The requested email already exists."));
			return true;
		end
		if pending_emails[user.email] then
			log("debug", "Attempt to register with pending email");
			session.send(st.error_reply(stanza, "cancel", "conflict", "The requested email is registering."));
			return true;
		end
		pending_registrations[user.user_id] = user;
		pending_usernames[user.username] = user.user_id;
		pending_emails[user.email] = user.user_id;
		pending_validation_codes[user.user_id] = id.short();

		local email_body = render_template(get_template("validation",".txt"), {code = pending_validation_codes[user.user_id]});
		local subject = mail_subject_prefix.."email validation";
		send_email(user.email, smtp_address, email_body, subject);
		module:fire_event("user-registering", user);
		local stanza_reply = st:reply(stanza)
		stanza_reply:tag("query", {xmlns = "moonshard:iq:register", user_id = user.user_id}):up();
		session.send(stanza_reply);
		timer.add_task(300, function()
			if pending_registrations[user.user_id] then
				pending_registrations[user.user_id] = nil;
				pending_usernames[user.username] = nil;
				pending_emails[user.email] = nil;
				pending_validation_codes[user.user_id] = nil;
			end
		end);
		return true;
	end
end)