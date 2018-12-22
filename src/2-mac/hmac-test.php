#!/usr/bin/env php
<?= hash_hmac_file($argv[1], "hmac-test-data", file_get_contents("hmac-test-key")) ?>
