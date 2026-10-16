--TEST--
ssh2_shell_test() - Tests opening a shell
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));
$shell = ssh2_shell($ssh);
var_dump($shell);

fwrite( $shell, 'echo "foo bar"'.PHP_EOL);
sleep(1);
$found = false;
while($line = fgets($shell)) {
    if (str_contains($line, 'foo bar') && !str_contains($line, 'echo')) {
        $found = true;
    }
}

var_dump($found);
--EXPECTF--
bool(true)
resource(%d) of type (stream)
bool(true)