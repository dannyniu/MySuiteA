#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
hmac-drbg-sha-t-test.c
hmac-drbg.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-hash/sha.c
1-symm/fips-180.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
