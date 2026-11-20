--TEST--
SFTP stream reports a server failure while closing an uploaded file
--SKIPIF--
<?php
if (!extension_loaded('ssh2')) die('skip ssh2 extension is not available');
if (!getenv('TEST_SSH2_CLOSE_DENIED_PORT') || !getenv('TEST_SSH2_CLOSE_ALLOWED_PORT')
    || !getenv('TEST_SSH2_CLOSE_KEY') || !getenv('TEST_SSH2_CLOSE_USER') || !getenv('TEST_SSH2_CLOSE_DIR')) {
    die('skip SFTP close test servers are not configured');
}
?>
--FILE--
<?php
$key = getenv('TEST_SSH2_CLOSE_KEY');
$user = getenv('TEST_SSH2_CLOSE_USER');
$dir = getenv('TEST_SSH2_CLOSE_DIR');

foreach ([
    [getenv('TEST_SSH2_CLOSE_ALLOWED_PORT'), false, 'data'],
    [getenv('TEST_SSH2_CLOSE_DENIED_PORT'), true, 'data'],
    [getenv('TEST_SSH2_CLOSE_ALLOWED_PORT'), false, ''],
    [getenv('TEST_SSH2_CLOSE_DENIED_PORT'), true, ''],
] as [$port, $shouldWarn, $content]) {
    $session = ssh2_connect('127.0.0.1', (int) $port);
    if (!$session || !ssh2_auth_pubkey_file($session, $user, $key . '.pub', $key)) {
        throw new RuntimeException('Could not authenticate to the SFTP fixture');
    }
    $sftp = ssh2_sftp($session);
    $path = $dir . '/' . uniqid('close-', true);
    $stream = fopen('ssh2.sftp://' . (int) $sftp . $path, 'x');
    if (!$stream || fwrite($stream, $content) !== strlen($content)) {
        throw new RuntimeException('Could not write the SFTP fixture');
    }
    $warning = null;
    set_error_handler(static function (int $level, string $message) use (&$warning): bool {
        $warning = $message;
        return true;
    }, E_WARNING);
    try {
        fclose($stream);
    } finally {
        restore_error_handler();
    }
    var_dump(($warning !== null) === $shouldWarn);
    if ($shouldWarn) {
        var_dump(str_contains($warning ?? '', 'SFTP CLOSE rejected (status 3)'));
    }
    if (!ssh2_sftp_unlink($sftp, $path)) {
        throw new RuntimeException('Could not clean up the SFTP fixture');
    }
    ssh2_disconnect($session);
}

$session = ssh2_connect('127.0.0.1', (int) getenv('TEST_SSH2_CLOSE_DENIED_PORT'));
if (!$session || !ssh2_auth_pubkey_file($session, $user, $key . '.pub', $key)) {
    throw new RuntimeException('Could not authenticate to the SFTP fixture');
}
$sftp = ssh2_sftp($session);
$path = $dir . '/' . uniqid('close-', true);
$stream = fopen('ssh2.sftp://' . (int) $sftp . $path, 'x');
if (!$stream || fwrite($stream, 'data') !== 4) {
    throw new RuntimeException('Could not write the SFTP fixture');
}
set_error_handler(static function (int $level, string $message): bool {
    throw new RuntimeException($message);
}, E_WARNING);
try {
    fclose($stream);
    echo "warning not raised\n";
} catch (RuntimeException $error) {
    var_dump(str_contains($error->getMessage(), 'SFTP CLOSE rejected (status 3)'));
} finally {
    restore_error_handler();
}
if (!ssh2_sftp_unlink($sftp, $path)) {
    throw new RuntimeException('Could not clean up the SFTP fixture');
}
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
