#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
hmac-drbg-sha-test.c
hmac-drbg-sha.c
hmac-drbg.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-hash/sha.c
1-symm/fips-180.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

echo ======== Test Name: $bin ========
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
