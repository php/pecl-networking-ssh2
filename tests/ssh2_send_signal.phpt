--TEST--
ssh2_send_signal() - Tests sending signal to process
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); 

if (!method_exists('ssh2_send_signal')) {
    print "skip no ssh2_send_signal()  (requires libssh2 1.11.0)";
}
?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));

$cmd = ssh2_exec($ssh, 'bash -c \'trap "echo success; exit 0" INT; echo ready; sleep 10; echo timeout\'');
var_dump($cmd);
stream_set_blocking($cmd, true);

echo fgets($cmd);

$result = ssh2_send_signal($cmd, 'INT');
var_dump($result);

echo stream_get_contents($cmd);

--EXPECTF--
bool(true)
resource(%d) of type (stream)
ready
bool(true)
success
