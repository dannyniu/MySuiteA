#!/bin/sh

testfunc() {
    e=0
    for b in 128 ; do
        for f in ../tests/KAT_SM4/ECB*${b}.rsp ; do
            exec1="$exec"
            if [ "$srcset" = "ARMv8.4-A Crypto Extensions" ]
            then exec1="qemu-aarch64 $exec" ; fi
            if ! $exec1 $b < $f ; then e=$((e+1)) ; echo fail: $b ; fi
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

src_common="sm4-test.c 0-datum/endian.c"

arch_family=defaults
cflags=""
srcset="Plain C"
src="sm4.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto+sm4 -D NI_SM4=NI_ALWAYS"
srcset="ARMv8.4-A Crypto Extensions"
src="sm4-arm.c"

tests_run
