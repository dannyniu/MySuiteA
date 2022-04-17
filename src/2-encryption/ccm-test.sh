#!/bin/sh

testdir1=../tests/ccmtestvectors

testfunc() {
    e=0;

    for s in 128 192 256 ; do
        for f in "$testdir1"/*$s.rsp
        do $exec CCM-AES-$s $f || e=$((e+1)) ; done
    done

    echo "$e test(s) failed."

    if [ $e -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ccm-test.c
ccm-aes.c
ccm.c
0-datum/endian.c
"

arch_family=defaults
cflags=""
srcset="Plain C"
src="
1-symm/rijndael.c
"

tests_run

arch_family=x86
cflags="-maes"
srcset="x86 AESNI"
src="1-symm/rijndael-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"

tests_run
