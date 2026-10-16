--TEST--
ssh2_exec() channel close respects stream timeout
--SKIPIF--
<?php
require('ssh2_skip.inc');
if (!function_exists('ssh2_set_timeout')) {
    die("skip ssh2_set_timeout not available");
}
?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
ssh2t_auth($ssh);

$start = microtime(true);

/* Run a command that takes much longer than our timeout */
$stream = ssh2_exec($ssh, 'sleep 60');
stream_set_timeout($stream, 3);

/* Without the fix, fclose() blocks for 60s waiting for
 * SSH_MSG_CHANNEL_CLOSE. With the fix, it respects the
 * stream timeout and returns in ~3s. */
fclose($stream);

$elapsed = microtime(true) - $start;

/* Should complete well under 10s. Without the fix this would take 60s. */
var_dump($elapsed < 10);
printf("Completed in %.1fs\n", $elapsed);
--EXPECTF--
bool(true)
Completed in %fs
