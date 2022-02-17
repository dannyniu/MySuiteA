#!/bin/sh

# 2021-09-13:
# This test had been added after CTR-DRBG:WithDF test succeeds,
# to test run-time instantiation functionalities.

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src_common="
ctr-drbg-aes-df-t-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

cflags=""
srcset="Plain C"
src="1-symm/rijndael.c"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

arch=x86_64
cflags="-maes"
srcset="AESNI"
src="1-symm/rijndael-x86.c"
( . $unitest_sh ) || ret=1

arch=aarch64
cflags="-march=armv8-a+crypto"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"
( . $unitest_sh ) || ret=1

exit $ret
