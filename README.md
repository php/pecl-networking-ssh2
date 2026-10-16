ssh2
====

Bindings for the libssh2 library.

Provides bindings to the functions of [libssh2](http:/libssh2.org/) which implements the SSH2 protocol.

[The ssh2 extension at the PECL Repository website](http://pecl.php.net/package/ssh2)

Documentation
=============

For documentation of the functions that this extension provides can be found here: http://www.php.net/ssh2

Build
=====

In this directory do:

```
phpize; ./configure; make
```

Tests
=====

The tests need a ssh server server to connect to. This can be done by ssh agent, username/password or through `ssh2_auth_none()`. 

Note that `ssh2_auth_pubkey.phpt` and `ssh2_auth_pubkey_file.phpt` require separate configuration. They require `TEST_SSH2_PUB_KEY` and `TEST_SSH2_PRIV_KEY` set to a valid public and private key file for the server you are connecting to for the tests.

ssh agent
---------

The testsuite can connect to the local machine using agent forwarding. This works if you have an identity on this system that is allow to connect through ssh on that same machine.

To get the tests working with ssh agent you need to alter `run-tests.php`. Normally for security reasons  `SSH_AUTH_SOCK` is not passed to tests, but if you want to use `ssh_auth_agent()` in your test run this is required.

```
sed -i '/SSH_AUTH_SOCK=deleted/d' run-tests.php

export TEST_SSH2_AUTH=agent
export TEST_SSH2_USER=anyone
export TEST_SSH2_HOSTNAME=127.0.0.1
export TEST_SSH2_PORT=22

make test
```

user/password
-------------

Username/password authentication is also supported for the tests.

```
export TEST_SSH2_AUTH=password
export TEST_SSH2_USER=anyone
export TEST_SSH2_PASS=Correct Horse Battery Staple
export TEST_SSH2_HOSTNAME=127.0.0.1
export TEST_SSH2_PORT=22

make test
```


`TEST_SSH2_USER` defaults to your local username. `TEST_SSH2_PORT` defaults to 22.


Contribute
==========

Your contributions and bugreports are highly appreciated. To contribute, fork and create a pull request. To report bugs use github issues.
