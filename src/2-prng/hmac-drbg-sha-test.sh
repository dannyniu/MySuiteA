#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
hmac-drbg-sha-test.c
hmac-drbg-sha.c
hmac-drbg.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-hash/sha.c
1-symm/fips-180.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
