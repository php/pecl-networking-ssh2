--TEST--
ssh2_poll() - Tests polling a channel for events
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
ssh2t_auth($ssh);

$stream = ssh2_exec($ssh, 'echo "poll test"');
stream_set_blocking($stream, false);

echo "**Poll with direct resource\n";
$polldesc = array(
    array(
        'resource' => $stream,
        'events' => SSH2_POLLIN,
    ),
);
$ready = ssh2_poll($polldesc, 5);
var_dump(is_int($ready));
var_dump($ready >= 0);

echo "**Poll result has revents\n";
var_dump(array_key_exists('revents', $polldesc[0]));

fclose($stream);
--EXPECT--
**Poll with direct resource
bool(true)
bool(true)
**Poll result has revents
bool(true)
