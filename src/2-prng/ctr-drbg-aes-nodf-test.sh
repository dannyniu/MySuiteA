#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ctr-drbg-aes-nodf-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"
cflags_common="-D CTR_DRBG_OMIT_DF"

arch_family=defaults
cflags=""
srcset="Plain C"
src="1-symm/rijndael.c"

tests_run

arch_family=x86
cflags="-maes"
srcset="AESNI"
src="1-symm/rijndael-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"

tests_run
