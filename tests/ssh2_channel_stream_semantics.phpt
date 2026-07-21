--TEST--
SSH2 channel streams distinguish backpressure, errors, and clean EOF
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

$nonblockingChannel = ssh2_exec($session, 'sleep 1; printf ready');

if ($nonblockingChannel === false) {
    throw new RuntimeException('Failed to open the nonblocking SSH channel.');
}

stream_set_blocking($nonblockingChannel, false);

var_dump(@fread($nonblockingChannel, 1) === '');
var_dump(!feof($nonblockingChannel));

fclose($nonblockingChannel);

$writeChannel = ssh2_exec($session, 'cat >/dev/null');

if ($writeChannel === false) {
    throw new RuntimeException('Failed to open the SSH write channel.');
}

stream_set_blocking($writeChannel, true);

var_dump(ssh2_send_eof($writeChannel));
var_dump(@fwrite($writeChannel, 'x') === false);
var_dump(!feof($writeChannel));

fclose($writeChannel);

$readChannel = ssh2_exec($session, 'true');

if ($readChannel === false) {
    throw new RuntimeException('Failed to open the SSH read channel.');
}

stream_set_blocking($readChannel, true);

var_dump(fread($readChannel, 1) === '');
var_dump(feof($readChannel));

fclose($readChannel);
ssh2_disconnect($session);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
