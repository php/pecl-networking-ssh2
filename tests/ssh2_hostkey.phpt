--TEST--
Raw host-key metadata and SHA-256 fingerprints describe the same server key
--SKIPIF--
<?php require('ssh2_skip.inc'); ?>
--FILE--
<?php
require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
$hostkey = ssh2_hostkey($ssh);
$fingerprint = ssh2_fingerprint($ssh, SSH2_FINGERPRINT_SHA256 | SSH2_FINGERPRINT_RAW);

var_dump(is_array($hostkey));
var_dump(is_string($hostkey['key']));
var_dump($hostkey['key'] !== '');
var_dump(is_int($hostkey['type']));
var_dump($hostkey['type'] !== SSH2_HOSTKEY_TYPE_UNKNOWN);
var_dump(strlen($fingerprint));
var_dump($fingerprint === hash('sha256', $hostkey['key'], true));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
int(32)
bool(true)
