#!/bin/bash


sudo adduser --disabled-password --gecos "" sshuser
echo "sshuser:sshpassword" | sudo chpasswd

phpize
./configure
make
make install

php -d variables_order=EGPCS run-tests.php -p $(which php) -d extension=$(pwd)/modules/ssh2.so -d variables_order=EGPCS -g "FAIL,XFAIL,BORK,WARN,LEAK,SKIP" --show-diff --offline --set-timeout 120