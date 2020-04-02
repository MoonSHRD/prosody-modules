prosody.unlock_globals()
local ltn12 = require "ltn12";
local json = require "util.json";
local http = require "socket.http";
local sasl = require "util.sasl";
local log = require "util.logger".init("auth_moonshard");
prosody.lock_globals()

rawset(_G, "PROXY", false) -- disable warnings about nil PROXY value

local post_url = module:get_option("auth_validate_token_url");
assert(post_url, "No token validation URL provided");

local provider = {};

function provider.test_password(username, password)
	return nil, "Not supported"
end

function provider.get_password(username)
	return nil, "Not supported"
end

function provider.set_password(username, password)
	return nil, "Not supported"
end

function provider.user_exists(username)
	return true;
end

function provider.create_user(username, password)
	return nil, "Not supported"
end


function provider.delete_user(username)
	return nil, "Not supported"
end

function provider.get_sasl_handler()
	local getpass_authentication_profile = {
		plain_test = function(sasl, username, password, realm)
			local postdata = json.encode({ accessToken = password });
			local respbody = {} -- for the response body
            http.request {
				method = "POST",
				url = post_url,
				source = ltn12.source.string(postdata),
				headers = {
					["content-type"] = "application/json",
					["content-length"] = tostring(#postdata)
				},
				sink = ltn12.sink.table(respbody)
			}
			respbody = table.concat(respbody)
			log("debug", respbody);
			local response = json.decode(respbody)
            if response and response.isValid == true then
                return true, true
            end
			return false, true;
		end,
	};
	return sasl.new(module.host, getpass_authentication_profile);
end



module:provides("auth", provider);

