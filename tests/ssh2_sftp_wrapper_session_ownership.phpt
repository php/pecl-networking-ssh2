--TEST--
Direct SFTP wrapper sessions are released with their streams
--SKIPIF--
<?php
require 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require 'ssh2_test.inc';

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
ssh2t_auth($ssh);

$sessionBaseline = count(get_resources('SSH2 Session'));
$sftpBaseline = count(get_resources('SSH2 SFTP'));
$path = ssh2t_tempnam();
$url = sprintf('ssh2.sftp://%s%s', $ssh, $path);

$stream = fopen($url, 'wb', false);

var_dump(is_resource($stream));
var_dump(fwrite($stream, 'test') === 4);
var_dump(fclose($stream));

gc_collect_cycles();

var_dump(count(get_resources('SSH2 SFTP')) === $sftpBaseline);
var_dump(count(get_resources('SSH2 Session')) === $sessionBaseline);

$session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

if ($session === false || !ssh2t_auth($session)) {
    throw new RuntimeException('Failed to connect to the SSH fixture.');
}

$sftp = ssh2_sftp($session);

if ($sftp === false || !ssh2_sftp_unlink($sftp, $path)) {
    throw new RuntimeException('Failed to clean up the SFTP fixture.');
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
