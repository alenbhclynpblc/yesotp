local yesotp = {
  _VERSION = "0.1"
}

-- luarocks install inspect, resty.jwt, resty.jwt-validators, resty.cookie, resty.mail, resty.validation, resty.template, resty.http

yesotp.__index = yesotp
local cjson = require('cjson')
local jwt = require('resty.jwt')
local jwt_validator = require('resty.jwt-validators')
local ck = require('resty.cookie')
local smtp = require('resty.mail')
local inspect = require('inspect')
local validation = require("resty.validation")
local template_engine = require("resty.template")
local http = require("resty.http")

function get_otp_token()
	local res = ""
	for i = 1,3 do
		res = res .. math.random(1,10) .. string.char(math.random(97, 122))
	end
	return res
end

local function split(s, delimiter)
    result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match);
    end
    return result;
end

local function get_config(group)
    if group == nil then
       return config_g
    end

    return config_g[group]
end

local function get_user_ip()
   return ngx.var.remote_addr
end

local function get_user_agent()
   return ngx.req.get_headers()["user-agent"]
end

local function generate_iss()
   return get_user_ip() .. "-" .. get_user_agent()
end

local function reset_cookies()
   local c = get_config("cookie")
   local cookie = ck:new()
   cookie:set({key=c["auth_cookie"], value="", expires="-3600"})
   cookie:set({key=c["preauth_cookie"], value="", expires="-3600"})
end

local function set_request_jwt_token(jwt_token)
   local cookie, err = ck:new()
   if not cookie then
      ngx.log(ngx.ERR, err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end

   local c = get_config("cookie")
   local resp, err = cookie:set({
      key= c["auth_cookie"], value=jwt_token,
      samesite= "Strict", httponly=true
   })

   if not resp then
      ngx.log(ngx.ERR, err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end
end

local function get_request_jwt_token()
   local cookie, err = ck:new()
   if not cookie then
      ngx.log(ngx.ERR, err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end

   local c = get_config("cookie")
   local resp, err = cookie:get(c["auth_cookie"])
   if not resp then
      return ""
   end

   return resp
end



local function notify_new_token(address, token)
   local c = get_config("smtp")
   local smtp_con, err = smtp.new({
       host= c["host"], 
       port= c["port"],
       username= c["username"],
       password= c["password"],
    })

    if err then
       ngx.log(ngx.ERR, "mail.new error: ", err)
       return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local response, err = smtp_con:send({
          from= c["from"],
          subject= c["subject"],
          to= { address },
          text = "You can find your access token below.\nToken: " .. token,
    })

    if err then
       ngx.log(ngx.ERR, "mailer:send error: ", err)
       return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
end

local function generate_jwt_token(stage_name, exp_time, extras)
    local c = get_config("jwt")

    if type(extras) ~= type({}) then
      extras = {}
    end

    jwt_token = jwt:sign(c["encryption_key"], {
          header={type="JWT", alg="HS256"},
          payload={
            exp= ngx.now() + exp_time, 
            iss= generate_iss(),
            extras=extras,
            stage=stage_name
          }
    })

    set_request_jwt_token(jwt_token)
end

local function verify_jwt_token(stage_name)
    local c = get_config("jwt")

    -- TODO: change lua-resty-jwt, this is the encryption key!
    local jwt_obj = jwt:verify(c["encryption_key"], get_request_jwt_token(), {
        exp= jwt_validator.is_not_expired(),
        iss= jwt_validator.equals(generate_iss()),
        stage= jwt_validator.equals(stage_name)
    })

    return jwt_obj["verified"]
end

function show_auth_page(message)
   ngx.status = 200
   ngx.header.content_type = "text/html"
   template_engine.render("auth.html", {
         form_method= "POST",
         form_path= "/mail-otp-auth.intf",
         form_message= message,
         input_name= "mail",
         input_placeholder= "E-Mail Address",
         button_text= "Send My Code",
         recaptcha_site_key= get_config("captcha")["site_key"],
   })
end

function show_verification_page(message)
   ngx.status = 200
   ngx.header.content_type = "text/html"
   template_engine.render("auth.html", {
         form_method= "POST",
         form_path= "/mail-otp-vrfy.intf",
         form_message= message,
         input_name= "vrfy",
         input_placeholder= "One Time Password",
         button_text= "Authorize Me",
         recaptcha_site_key= get_config("captcha")["site_key"],
   })
end

local function verify_email_input(mail)
   if validation.email(mail) == false then
      return false
   end

   local auth_conf = get_config("authorization")
   local lastAt = mail:find("[^%@]+$")

   -- validate.email does not able to cache "test@" inputs so we are gonna check is there something.
   if lastAt == nil then
      return false
   end

   local domain = mail:sub(lastAt, #mail)

   if auth_conf["whitelistdomains"][domain] ~= nil then
      return true
   end

   for key, value in pairs(auth_conf["whitelistdomains"]) do
        if value == domain then return true end
   end

   for key, value in pairs(auth_conf["whitelistaddresses"]) do
        if value == mail then return true end
   end

   return false
end

local function verify_captcha_response(user_response)
      local r = http.new()
      local res, err = r:request_uri("https://www.google.com/recaptcha/api/siteverify", {
            method= "POST",
            body= "secret=" .. get_config("captcha")["secret_key"] .. "&response=" .. user_response,
            headers = {
                   ["Content-Type"] = "application/x-www-form-urlencoded",
            },
      })

      if not res then
        ngx.log(ngx.ERR, "failed to request recaptcha verification request: ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
      end

      return cjson.decode(res.body)["success"]
end

function yesotp.make_me_safe(config)

   config_g = config
   local url = string.gsub(ngx.var.request_uri, "?.*", "")

   local parts = split(ngx.var.uri, "/")
   if parts[2] ~= nil and parts[2] == "yesotp-public" then
      return
   end

   if url == "/mail-otp-auth.intf" then
      -- Authentication form & i will send you a mail with token & will give you a JWT token :-)
      local verification_error = ""

      -- IF THERE IS A POST and we will gonna accept this page.
      if ngx.req.get_method() == "POST" then
         local captcha_response = ngx.req.get_post_args()["g-recaptcha-response"]
         local mail_addr = ngx.req.get_post_args()["mail"]
         if verify_captcha_response(captcha_response) ~= true then
            verification_error = "Captcha please."
         elseif verify_email_input(ngx.req.get_post_args()["mail"]) == false then
            verification_error = "You are not authorized for this destination."
         else
            local otp_token = get_otp_token()
            notify_new_token(ngx.req.get_post_args()["mail"], otp_token)
            generate_jwt_token(otp_token, 60*2)
            show_verification_page("You have 120 seconds for verification.")
            return
         end
      end

      if ngx.var.arg_failed ~= nil then
         verification_error = "Not accepted. Please try again."
      end

      show_auth_page(verification_error)
      return
   end

   if url == "/mail-otp-vrfy.intf" then
      if ngx.req.get_method() ~= "POST" then
         ngx.redirect("/mail-otp-auth.intf?1", 302)
         return
      end

      local captcha_response = ngx.req.get_post_args()["g-recaptcha-response"]
      local vrfy_code = ngx.req.get_post_args()["vrfy"]

      if captcha_response == nil or vrfy_code == nil then
          ngx.redirect("/mail-otp-auth.intf", 302)
      end

      if verify_captcha_response(captcha_response) == true and verify_jwt_token(vrfy_code) == true then
         generate_jwt_token("SIGNED", 60*60*4) -- This stage name will be the verified
         ngx.redirect("/")
         return
      else
          ngx.redirect("/mail-otp-auth.intf?failed=1")
      end

      return
   end

   if verify_jwt_token("SIGNED") == false then
      ngx.redirect("/mail-otp-auth.intf", 302)
      return
   else
      -- All is well.. So you can pass without problem.
   end

end

return yesotp
