## YESOTP 
### About

This tool is designed for OTP based access control management. Nothing big or shiny, it will deploy a tiny lua script and will work over OpenResty (Nginx).

### Structure

Client <=> Reverse Proxy with YESOTP <=> HTTP Server

All requests will be passed over YESOTP reverse proxy server, if user is already authenticated nothing to do, otherwise application will not allow to access.

### Logon Pages
Thanks for free template :-)
![alt text](https://raw.githubusercontent.com/alenbhclynpblc/yesotp/master/_img/email.png)
![alt text](https://raw.githubusercontent.com/alenbhclynpblc/yesotp/master/_img/otp.png)

### Needs
##### User Validation
- You can allow a domain address for all e-mails (ex: test.com will cover all X@test.com)
- You can specify every single e-mail address
- both options can be used at single deployment for example allow all e-mails for test.com and specific.user@partner.com

##### Captcha
You will need Google reCaptcha V2 configuration

##### SMTP
You will need and SMTP endpoint for mails. 

### Installation

- OpenResty - Scalable Web Platform by Extending NGINX with Lua @ https://openresty.org/en/download.html
- Lua Packages
  - resty.jwt
  - resty.jwt-validators
  - resty.cookie
  - resty.mail
  - resty.validation
  - resty.template
  - resty.http

##### Ubuntu
```bash
# Note: if nginx is already installed and running, try disabling and stopping it before installing openresty like below:
sudo systemctl disable nginx;
sudo systemctl stop nginx; 

# Lets install OpenResty
wget -qO - https://openresty.org/package/pubkey.gpg | sudo apt-key add -;
sudo apt-get -y install software-properties-common;
sudo add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main";
sudo apt-get update;
sudo apt-get install libpcre3-dev libssl-dev perl make build-essential curl;
sudo apt-get install lua5.3;
sudo apt-get install openresty;
sudo apt-get install luarocks;

# Lets install packages which we need
luarocks install lua-resty-cookie;
luarocks install lua-resty-http;
luarocks install lua-resty-jwt;
luarocks install lua-resty-mail;
luarocks install lua-resty-openidc;
luarocks install lua-resty-session;
luarocks install lua-resty-template;
luarocks install lua-resty-url;
luarocks install lua-resty-validation;

# Lets make our directory
cp -r yesotp /etc/yesotp/;

# Configure your nginx.conf file buddy :-)
nano /usr/local/openresty/nginx/conf/nginx.conf

# Lets start our service :-)
sudo openresty;
```

##### Debian Jessie or Later
```bash
# Note: if nginx is already installed and running, try disabling and stopping it before installing openresty like below:
sudo systemctl disable nginx;
sudo systemctl stop nginx; 

# Lets install OpenResty
wget -qO - https://openresty.org/package/pubkey.gpg | sudo apt-key add -;
sudo apt-get -y install software-properties-common;
sudo add-apt-repository -y "deb http://openresty.org/package/debian $(lsb_release -sc) openresty";
sudo apt-get update;
sudo apt-get install openresty;

# Lets install luarocks for package management.
# For more help: https://github.com/luarocks/luarocks/wiki/Installation-instructions-for-Unix
wget https://luarocks.org/releases/luarocks-3.0.4.tar.gz;
tar zxpf luarocks-3.0.4.tar.gz;
cd luarocks-3.0.4;
./configure; 
make build;
make install;

# Lets install packages which we need
luarocks install lua-resty-cookie;
luarocks install lua-resty-http;
luarocks install lua-resty-jwt;
luarocks install lua-resty-mail;
luarocks install lua-resty-openidc;
luarocks install lua-resty-session;
luarocks install lua-resty-template;
luarocks install lua-resty-url;
luarocks install lua-resty-validation;

# Lets make our directory
cp -r yesotp /etc/yesotp/;

# Configure your nginx.conf file buddy :-)
nano /usr/local/openresty/nginx/conf/nginx.conf
```
## Example Configuration

```nginx
http {
        # lua will import yesotp.lua file from that path.
        lua_package_path "/etc/yesotp/lua/?.lua;;";

        upstream myapp {
             server X.X.X.X; # Write your applications IP address.
        }

        server {
                listen       80;
                server_name  paymentapi.gkfxprime.com;
                access_log   /var/log/nginx/access-custom.log;
                root /var/www;

                resolver 8.8.8.8 ipv6=off;

                #You need trusted root certificate definition, otherwise recaptcha request will gonna fail.
                ### How-to-guide;
                ### cp /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.pem :-)
                lua_ssl_verify_depth 2;
                lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.pem;

                # This files will be used at logon pages (css/js/etc)
                location /yesotp-public {
                    alias /etc/yesotp/web/public/;
                }

                # Template for logon page.
                set $template_root /etc/yesotp/web/template/;
				
				# We will gonna need URL & BODY arguments at logon.
                lua_need_request_body on;
				
                location / {
                        access_by_lua_block {
                           local opts= {
                              jwt= {
                                  encryption_key= "MAKE_ME_SECRET_AND_LONG",
                                  additional_details= {},
                              },
                              cookie= {
                                  auth_cookie= "YESOTP_AUTH",
                              },
                              smtp= {
                                  host= "SMTP-Server.MyDomainAddress.org",
                                  port= 25,
                                  username= nil,
                                  password= nil,
                                  from= "web-otp@MyDomainAddress.com",
                                  subject= "OTP Code for your web access.",
                              },
                              authorization= {
                                  whitelistdomains= {"MyDomainAddress.com"},
                                  whitelistaddresses= {"single.user@MyDomainAddress.com"}
                              },

                              captcha= {
                                  site_key= "reCaptchaV2 Key",
                                  secret_key= "reCaptchaV2 Key"
                              }
                           }

                           require("yesotp").make_me_safe(opts)
                        }

                        proxy_set_header Host $host;
                        proxy_set_header X-Forwarded-For $remote_addr;
                        proxy_pass http://myapp;
                }

          }
```

## Deployment Checklist

- Did you defined "resolver X.X.X.X" ? 
- Did you defined ipv6=off; at "resolver X.X.X.X ipv6=off;" ? 
- Did you defined lua_package_path ?
- Did you defined lua_ssl_verify_depth & lua_ssl_trusted_certificate ?
- Did you defined "location /yesotp-public" block ?
- Did you defined "set $template_root /etc/yesotp/web/template/;" ?
- Did you defined "lua_need_request_body on;" ?
- Did you defined "access_by_lua_block" code block at "location /" block ?

Not solved? Check /usr/local/openresty/nginx/logs/error.log file :-)
