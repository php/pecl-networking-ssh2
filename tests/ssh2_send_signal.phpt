--TEST--
ssh2_send_signal() - Tests sending signal to process
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));

$cmd = ssh2_exec($ssh, 'bash -c \'trap "echo success" SIGINT; sleep infinity\'');
var_dump($cmd);

$result = ssh2_send_signal($cmd, 'INT');
var_dump($result);

$stdout = stream_get_contents($cmd);
echo $stdout;

--EXPECTF--
bool(true)
resource(%d) of type (stream)
bool(true)
success