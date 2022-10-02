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

arch_family=defaults
cflags=""
srcset="Plain C"
src="1-symm/rijndael.c"

tests_run

arch_family=x86
cflags="-maes -D NI_AES=NI_ALWAYS"
srcset="x86 AESNI"
src="1-symm/rijndael-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto -D NI_AES=NI_ALWAYS"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"

tests_run

arch_family=ppc
cflags="-mcpu=power8 -D NI_AES=NI_ALWAYS"
srcset="PowerPC AltiVec Crypto"
src="1-symm/rijndael-ppc.c"

tests_run
