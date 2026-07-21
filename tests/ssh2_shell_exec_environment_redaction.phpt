--TEST--
Shell and exec environment warnings do not expose values
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

$secret = 'secret-value-must-not-appear';
$warnings = [];

set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
    if ($severity !== E_WARNING || !str_contains($message, 'Failed setting environment variable')) {
        return false;
    }

    $warnings[] = $message;

    return true;
});

try {
    $environment = ['PHP_SSH2_REDACTION_TEST' => $secret];
    $shell = ssh2_shell($session, 'xterm', $environment, 80, 24);
    $stream = ssh2_exec($session, 'true', null, $environment);
} finally {
    restore_error_handler();
}

var_dump(is_resource($shell));
var_dump(is_resource($stream));

foreach ($warnings as $warning) {
    echo $warning, PHP_EOL;
}

var_dump(count($warnings));
var_dump(str_contains(implode("\n", $warnings), $secret));

if (is_resource($shell)) {
    fclose($shell);
}

if (is_resource($stream)) {
    fclose($stream);
}

ssh2_disconnect($session);
?>
--EXPECT--
bool(true)
bool(true)
ssh2_shell(): Failed setting environment variable PHP_SSH2_REDACTION_TEST on remote end
ssh2_exec(): Failed setting environment variable PHP_SSH2_REDACTION_TEST on remote end
int(2)
bool(false)
