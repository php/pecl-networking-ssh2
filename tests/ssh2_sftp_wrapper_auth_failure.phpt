--TEST--
Direct SFTP wrapper authentication failures release their sessions
--SKIPIF--
<?php
require 'ssh2_skip.inc';
ssh2t_needs_auth();

if (!is_dir('/proc/self/fd')) {
    echo 'skip requires /proc/self/fd';
}
?>
--FILE--
<?php
require 'ssh2_test.inc';

$context = stream_context_create([
    'ssh2' => [
        'username' => TEST_SSH2_USER,
        'password' => 'invalid-ssh2-test-password',
    ],
]);
$url = sprintf(
    'ssh2.sftp://%s:%d%s/missing.txt',
    TEST_SSH2_HOSTNAME,
    TEST_SSH2_PORT,
    rtrim(TEST_SSH2_TEMPDIR, '/'),
);
$fileDescriptorCount = static fn (): int => count(scandir('/proc/self/fd')) - 2;

$baseline = $fileDescriptorCount();
$authenticationFailed = @fopen($url, 'rb', false, $context) === false;

gc_collect_cycles();

var_dump($authenticationFailed);
var_dump($fileDescriptorCount() === $baseline);
?>
--EXPECT--
bool(true)
bool(true)
