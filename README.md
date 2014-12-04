userapp-nginx
=============

Perform UserApp.io authentication at the webserver.

Once authenticated with UserApp.io, your app will send a HTTP Basic Authentication header along with every request. This nginx lua module will intercept that token and verify it with UserApp.io.

It will also append all the permissions, features and properties of the user to the header. This will make it easy for any upstream applications to get info about the user.


## Requirements
You will need OpenResty or nginx compiled with lua support.

	sudo apt-add-repository -y ppa:nginx/stable
	sudo apt-get -qq update
	sudo apt-get -qqy install nginx-extras
	sudo apt-get install -y libssl-dev libcurl3-dev lua5.1 luarocks

	luarocks install luasec OPENSSL_LIBDIR=/usr/lib/x86_64-linux-gnu
	luarocks install Lua-cURL
	luarocks install penlight
	luarocks install lua-cjson

Check the nginx-sites for example.