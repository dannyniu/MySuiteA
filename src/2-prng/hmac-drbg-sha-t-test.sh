#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
hmac-drbg-sha-t-test.c
hmac-drbg.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-hash/sha.c
0-datum/endian.c
"

. ../1-symm/fips-180-variants.sh.inc
