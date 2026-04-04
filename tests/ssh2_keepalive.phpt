--TEST--
ssh2_keepalive_config() and ssh2_keepalive_send() basic functionality
--SKIPIF--
<?php
require('ssh2_skip.inc');
if (!function_exists('ssh2_keepalive_config') || !function_exists('ssh2_keepalive_send')) {
    die("skip keepalive support not available");
}
?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

echo "**Configure keepalive\n";
ssh2_keepalive_config($ssh, true, 10);

echo "**Send keepalive\n";
$seconds = ssh2_keepalive_send($ssh);
var_dump(is_int($seconds));
var_dump($seconds > 0);

echo "**Disable keepalive\n";
ssh2_keepalive_config($ssh, false, 0);
$seconds = ssh2_keepalive_send($ssh);
var_dump($seconds === 0);
--EXPECT--
**Configure keepalive
**Send keepalive
bool(true)
bool(true)
**Disable keepalive
bool(true)
