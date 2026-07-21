--TEST--
SSH2 child resources fail safely after their parent session is closed
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
$sessionBaseline = count(get_resources('SSH2 Session'));
$sftpBaseline = count(get_resources('SSH2 SFTP'));

$channelSession = $connect();
$channel = ssh2_exec($channelSession, 'cat');

if ($channel === false) {
    throw new RuntimeException('Failed to open an SSH channel.');
}

$stderr = ssh2_fetch_stream($channel, SSH2_STREAM_STDERR);

if ($stderr === false) {
    throw new RuntimeException('Failed to open the channel stderr stream.');
}

var_dump(ssh2_disconnect($channelSession));
var_dump(@fwrite($channel, 'test') === false);
var_dump(@fread($channel, 1) === false);
var_dump(feof($channel));
var_dump(!@fflush($channel));
var_dump(!ssh2_shell_resize($channel, 80, 24));
var_dump(!ssh2_send_eof($channel));
var_dump(!function_exists('ssh2_send_signal') || !ssh2_send_signal($channel, 'TERM'));
var_dump(ssh2_fetch_stream($channel, SSH2_STREAM_STDERR) === false);

$poll = [['resource' => $channel, 'events' => SSH2_POLLIN]];
var_dump(@ssh2_poll($poll, 0) === 0);
var_dump(fclose($stderr));
var_dump(fclose($channel));

unset($stderr, $channel, $channelSession);

$sftpSession = $connect();
$sftp = ssh2_sftp($sftpSession);

if ($sftp === false) {
    throw new RuntimeException('Failed to open the SFTP subsystem.');
}

$root = ssh2t_tempnam();
$filePath = $root . '/file.txt';
$otherPath = $root . '/other.txt';
$linkPath = $root . '/link.txt';

if (!ssh2_sftp_mkdir($sftp, $root, 0700)) {
    throw new RuntimeException('Failed to create the SFTP fixture directory.');
}

$file = fopen('ssh2.sftp://' . (int) $sftp . $filePath, 'w+');
$directory = opendir('ssh2.sftp://' . (int) $sftp . $root);

if ($file === false || $directory === false) {
    throw new RuntimeException('Failed to open the SFTP fixture streams.');
}

var_dump(ssh2_disconnect($sftpSession));
var_dump(@fwrite($file, 'test') === false);
var_dump(@fread($file, 1) === false);
var_dump(fseek($file, 0, SEEK_END) === -1);
var_dump(fstat($file) === false);
var_dump(readdir($directory) === false);
var_dump(feof($directory) === false);
var_dump(!ssh2_sftp_rename($sftp, $filePath, $otherPath));
var_dump(!ssh2_sftp_unlink($sftp, $filePath));
var_dump(!ssh2_sftp_mkdir($sftp, $otherPath));
var_dump(!ssh2_sftp_rmdir($sftp, $root));
var_dump(!ssh2_sftp_chmod($sftp, $filePath, 0600));
var_dump(ssh2_sftp_stat($sftp, $filePath) === false);
var_dump(ssh2_sftp_lstat($sftp, $filePath) === false);
var_dump(!ssh2_sftp_symlink($sftp, $filePath, $linkPath));
var_dump(ssh2_sftp_readlink($sftp, $linkPath) === false);
var_dump(ssh2_sftp_realpath($sftp, $filePath) === false);
var_dump(fclose($file));
closedir($directory);

unset($directory, $file, $sftp, $sftpSession);

$cleanupSession = $connect();
$cleanupSftp = ssh2_sftp($cleanupSession);

if ($cleanupSftp === false
    || !ssh2_sftp_unlink($cleanupSftp, $filePath)
    || !ssh2_sftp_rmdir($cleanupSftp, $root)) {
    throw new RuntimeException('Failed to clean up the SFTP fixture.');
}

unset($cleanupSftp);
ssh2_disconnect($cleanupSession);
unset($cleanupSession);

$listenerSession = $connect();
$listener = ssh2_forward_listen($listenerSession, 0);

if ($listener === false) {
    throw new RuntimeException('Failed to open an SSH remote-forward listener.');
}

var_dump(ssh2_disconnect($listenerSession));
var_dump(ssh2_forward_accept($listener) === false);

$poll = [['resource' => $listener, 'events' => SSH2_POLLIN]];
var_dump(@ssh2_poll($poll, 0) === 0);

unset($listener, $listenerSession);
gc_collect_cycles();

var_dump(count(get_resources('SSH2 SFTP')) === $sftpBaseline);
var_dump(count(get_resources('SSH2 Session')) === $sessionBaseline);
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
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
