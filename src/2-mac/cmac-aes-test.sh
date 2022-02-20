#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
cmac-aes-test.c
cmac-aes.c
cmac.c
0-datum/endian.c
"

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
