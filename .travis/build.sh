#!/bin/bash

sudo adduser --disabled-password --gecos "" sshuser
echo "sshuser:sshpassword" | sudo chpasswd
sudo mkdir -p ~sshuser/.ssh
sudo chown sshuser:sshuser ~sshuser/.ssh
sudo sh -c "cat $(pwd)/tests/testkey_rsa.pub >> ~sshuser/.ssh/authorized_keys"
sudo chown sshuser:sshuser ~sshuser/.ssh/authorized_keys
sudo chmod 600 ~sshuser/.ssh/authorized_keys

phpize
./configure
make
make install

php -d variables_order=EGPCS run-tests.php -p $(which php) -d extension=$(pwd)/modules/ssh2.so -d variables_order=EGPCS -g "FAIL,XFAIL,BORK,WARN,LEAK,SKIP" --show-diff --offline --set-timeout 120
