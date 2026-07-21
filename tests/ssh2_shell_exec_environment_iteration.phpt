--TEST--
Shell and exec environment arrays are traversed safely
--SKIPIF--
<?php
require 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require 'ssh2_test.inc';

final class EnvironmentValue
{
    public static array $converted = [];

    public function __construct(private string $value)
    {
    }

    public function __toString(): string
    {
        self::$converted[] = $this->value;

        return $this->value;
    }
}

$session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

if ($session === false || !ssh2t_auth($session)) {
    throw new RuntimeException('Failed to connect to the SSH fixture.');
}

$shell = ssh2_shell($session, 'xterm', [], 80, 24);

var_dump(is_resource($shell));

if (is_resource($shell)) {
    fclose($shell);
}

$stream = @ssh2_exec($session, 'true', null, [
    'PHP_SSH2_TEST_A' => new EnvironmentValue('alpha'),
    'PHP_SSH2_TEST_B' => new EnvironmentValue('bravo'),
]);

var_dump(EnvironmentValue::$converted);

if (is_resource($stream)) {
    fclose($stream);
}

ssh2_disconnect($session);
?>
--EXPECT--
bool(true)
array(2) {
  [0]=>
  string(5) "alpha"
  [1]=>
  string(5) "bravo"
}
