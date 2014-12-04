-- Authenticate request against UserApp.io

function table.find(array, element) -- find element v of l satisfying f(v)
    for k, v in pairs(array) do
        if v == element then
            return true
        end
    end
    return false
end

-- get a list of all keys in table which are marked with value 'true'
-- also sets headers
function extractAuthorizations(table, prefix)
    local keys = {}
    for k, v in pairs(table) do
        ngx.req.set_header(prefix .. "_" .. k, tostring(v["value"]))
        if tostring(v["value"]) == "true" then
            keys[#keys+1] = k
        end
    end
    return keys
end

-- string split utility (http://stackoverflow.com/questions/1426954/split-string-in-lua)
function split(pString, pPattern)
  local Table = {}  -- NOTE: use {n = 0} in Lua-5.0
  local fpat = "(.-)" .. pPattern
  local last_end = 1

  local s, e, cap = pString:find(fpat, 1)
  while s do
    if s ~= 1 or cap ~= "" then
       table.insert(Table,cap)
    end

    last_end = e + 1
    s, e, cap = pString:find(fpat, last_end)
  end

  if last_end <= #pString then
    cap = pString:sub(last_end)
    table.insert(Table, cap)
  end

  return Table
end

-- checks if one table is fully present in another
function isSuperSet(parent, child)
    if type(parent) ~= type(child) then return false end
    for k, v in pairs(child) do
        if table.find(parent, v) == false then
            return false
        end
    end
    return true
end


-- grab authorization header
local auth_header = ngx.req.get_headers().authorization

-- check that the header is valid
if not auth_header or auth_header == '' or not string.match(auth_header, '^[Bb]asic ') then
    -- No Auth header found, redirect to login page
    ngx.log(ngx.ALERT, "[INTRUSION] Request without auth header: " .. ngx.var.remote_addr);
    return ngx.redirect("/login")
end

local pretty = require 'pl.pretty'

-- decode authenication header and extract session token
local tokenTable = split(ngx.decode_base64(split(auth_header, ' ')[2])..'', ':')
local token = table.remove(tokenTable, 1)

if not token then
    -- token was not found
    ngx.log(ngx.ALERT, "[INTRUSION] Request with invalid session token: " .. ngx.var.remote_addr);
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- fast json parser
local cjson = require "cjson"

-- function to execute once request to UserApp is complete
local function requestComplete(rawResponse)
  local response = cjson.decode(rawResponse)
  -- ngx.log(ngx.INFO, pretty.write(response));

  -- check if token is invalid by checking if an error_code is present
  if (response["error_code"] ~= nil) then
      ngx.log(ngx.ALERT, "[INTRUSION] Request with token: " .. token .. " not recognized by UserApp: " .. ngx.var.remote_addr);
      ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  -- extract user data and permissions from response
  local userData = response[1];
  local permissions = extractAuthorizations(userData.permissions, "user_permission")
  local features = extractAuthorizations(userData.features, "user_feature")

  -- verify if user has required permissions
  if ngx.var.permissions_required and ngx.var.permissions_required ~= "" then
      local permissions_required = split(ngx.var.permissions_required, ",");
      if isSuperSet(permissions, permissions_required) == false then
          -- permission was not found
          ngx.log(ngx.ALERT, "[INTRUSION] User does not have required permissions: " .. userData.login);
          ngx.exit(ngx.HTTP_UNAUTHORIZED)
      end
  end

  -- verify if user has required features
  if ngx.var.features_required and ngx.var.features_required ~= "" then
      local features_required = split(ngx.var.features_required, ",");
      if isSuperSet(features, features_required) == false then
          -- feature was not found
          ngx.log(ngx.ALERT, "[INTRUSION] User does not have required features: " .. userData.login);
          ngx.exit(ngx.HTTP_UNAUTHORIZED)
      end
  end

  -- set user properties as individual headers
  for k, v in pairs(userData.properties) do
    ngx.req.set_header("user_property_" .. k, tostring(v["value"]))
  end

  -- set some headers
  ngx.req.set_header("user_id", tostring(userData.user_id))
  ngx.req.set_header("user_first_name", tostring(userData.first_name))
  ngx.req.set_header("user_last_name", tostring(userData.last_name))
  ngx.req.set_header("user_email", tostring(userData.email))
  ngx.req.set_header("user_login", tostring(userData.login))
  ngx.req.set_header("user_last_login_at", tostring(userData.last_login_at))

  ngx.log(ngx.NOTICE, "User has required permissions to access this resource: " .. userData.login);
end


local curl = require "cURL"

-- Make request as per https://app.userapp.io/#/docs/user/#get
-- Remeber to update your key
local request = curl.easy({
  url        = "https://<your-key>:" .. token .. "@api.userapp.io/v1/user.get",
  post       = true,
  httpheader = {
    "user_id: self",
  },
  writefunction = requestComplete,
})

request:perform()
