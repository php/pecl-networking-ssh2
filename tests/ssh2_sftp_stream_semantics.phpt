--TEST--
SFTP streams distinguish errors from clean completion
--SKIPIF--
<?php
require 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require 'ssh2_test.inc';

$connect = static function () {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    return $session;
};
$root = ssh2t_tempnam();
$filePath = $root . '/file.txt';
$session = $connect();
$sftp = ssh2_sftp($session);

if ($sftp === false
    || !ssh2_sftp_mkdir($sftp, $root, 0700)
    || file_put_contents('ssh2.sftp://' . (int) $sftp . $filePath, 'test') !== 4) {
    throw new RuntimeException('Failed to create the SFTP fixture.');
}

$failedRead = fopen('ssh2.sftp://' . (int) $sftp . $filePath, 'rb');
$failedDirectory = opendir('ssh2.sftp://' . (int) $sftp . $root);

if ($failedRead === false || $failedDirectory === false) {
    throw new RuntimeException('Failed to open the SFTP failure streams.');
}

var_dump(ssh2_disconnect($session));
var_dump(@fread($failedRead, 1) === false);
var_dump(!feof($failedRead));
var_dump(readdir($failedDirectory) === false);
var_dump(!feof($failedDirectory));

fclose($failedRead);
closedir($failedDirectory);
unset($failedRead, $failedDirectory, $sftp, $session);

$session = $connect();
$sftp = ssh2_sftp($session);

if ($sftp === false) {
    throw new RuntimeException('Failed to reopen the SFTP subsystem.');
}

$cleanRead = fopen('ssh2.sftp://' . (int) $sftp . $filePath, 'rb');
$cleanDirectory = opendir('ssh2.sftp://' . (int) $sftp . $root);

if ($cleanRead === false || $cleanDirectory === false) {
    throw new RuntimeException('Failed to open the SFTP completion streams.');
}

var_dump(fread($cleanRead, 4) === 'test');
var_dump(fread($cleanRead, 1) === '');
var_dump(feof($cleanRead));

$entries = [];

while (($entry = readdir($cleanDirectory)) !== false) {
    $entries[] = $entry;
}

sort($entries, SORT_STRING);

var_dump($entries === ['.', '..', 'file.txt']);
var_dump(feof($cleanDirectory));

fclose($cleanRead);
closedir($cleanDirectory);

if (!ssh2_sftp_unlink($sftp, $filePath) || !ssh2_sftp_rmdir($sftp, $root)) {
    throw new RuntimeException('Failed to clean up the SFTP fixture.');
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
