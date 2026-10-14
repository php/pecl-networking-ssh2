--TEST--
ssh2_shell() validates paired terminal dimensions
--SKIPIF--
<?php
require 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require 'ssh2_test.inc';

$session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

if ($session === false || !ssh2t_auth($session)) {
    throw new RuntimeException('Failed to connect to the SSH fixture.');
}

$shell = ssh2_shell($session, 'xterm', [], 80, 24);

var_dump(is_resource($shell));

if (is_resource($shell)) {
    fclose($shell);
}

var_dump(ssh2_shell($session, 'xterm', [], 80));

ssh2_disconnect($session);
?>
--EXPECTF--
bool(true)

Warning: ssh2_shell(): width specified without height parameter in %s on line %d
bool(false)
