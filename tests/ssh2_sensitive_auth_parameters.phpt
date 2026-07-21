--TEST--
SSH2 authentication parameters publish sensitive metadata and redact traces
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) {
    echo 'skip SensitiveParameter requires PHP 8.2 or newer';
}
if (!extension_loaded('ssh2')) {
    echo 'skip extension not loaded';
}
?>
--INI--
zend.exception_ignore_args=0
--FILE--
<?php
$sensitiveParameters = [
    ['ssh2_auth_password', 'password'],
    ['ssh2_auth_pubkey_file', 'passphrase'],
    ['ssh2_auth_pubkey', 'privkey'],
    ['ssh2_auth_pubkey', 'passphrase'],
    ['ssh2_auth_hostbased_file', 'passphrase'],
];

foreach ($sensitiveParameters as [$function, $parameter]) {
    $reflectionParameter = new ReflectionParameter($function, $parameter);

    printf(
        "%s:%s sensitive: %s\n",
        $function,
        $parameter,
        count($reflectionParameter->getAttributes(SensitiveParameter::class)) === 1 ? 'true' : 'false',
    );
}

$ordinaryParameters = [
    ['ssh2_auth_password', 'username'],
    ['ssh2_auth_pubkey', 'pubkey'],
    ['ssh2_auth_pubkey_file', 'privkeyfile'],
    ['ssh2_auth_hostbased_file', 'privkeyfile'],
];

foreach ($ordinaryParameters as [$function, $parameter]) {
    $reflectionParameter = new ReflectionParameter($function, $parameter);

    printf(
        "%s:%s sensitive: %s\n",
        $function,
        $parameter,
        $reflectionParameter->getAttributes(SensitiveParameter::class) === [] ? 'false' : 'true',
    );
}

try {
    ssh2_auth_password(null, 'trace-user', 'trace-secret');
} catch (Throwable $exception) {
    $arguments = $exception->getTrace()[0]['args'];
    $trace = print_r($exception->getTrace(), true);

    printf("trace username: %s\n", $arguments[1]);
    printf("trace password wrapped: %s\n", $arguments[2] instanceof SensitiveParameterValue ? 'true' : 'false');
    printf("trace contains secret: %s\n", str_contains($trace, 'trace-secret') ? 'true' : 'false');
}
?>
--EXPECT--
ssh2_auth_password:password sensitive: true
ssh2_auth_pubkey_file:passphrase sensitive: true
ssh2_auth_pubkey:privkey sensitive: true
ssh2_auth_pubkey:passphrase sensitive: true
ssh2_auth_hostbased_file:passphrase sensitive: true
ssh2_auth_password:username sensitive: false
ssh2_auth_pubkey:pubkey sensitive: false
ssh2_auth_pubkey_file:privkeyfile sensitive: false
ssh2_auth_hostbased_file:privkeyfile sensitive: false
trace username: trace-user
trace password wrapped: true
trace contains secret: false
