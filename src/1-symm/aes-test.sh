#!/bin/sh

testfunc() {
    e=0
    for b in 128 192 256 ; do
        for f in ../tests/KAT_AES/ECB*${b}.rsp ; do
            $exec $b < $f || e=$((e+1))
        done
    done
    echo "$e set(s) of test vectors failed."
    if [ $e -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
aes-test.c
0-datum/endian.c
"

arch_family=defaults
cflags=""
srcset="Plain C"
src="rijndael.c"

tests_run

arch_family=x86
cflags="-maes -D NI_AES=NI_ALWAYS"
srcset="AESNI"
src="rijndael-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto -D NI_AES=NI_ALWAYS"
srcset="ARM NEON Crypto"
src="rijndael-arm.c"

tests_run
