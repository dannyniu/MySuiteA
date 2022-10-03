#!/bin/sh

# 2021-09-13:
# This test had been added after CTR-DRBG:WithDF test succeeds,
# to test run-time instantiation functionalities.

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ctr-drbg-aes-df-t-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"

. ../1-symm/rijndael-variants.sh.inc
