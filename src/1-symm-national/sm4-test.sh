#!/bin/sh

testfunc() {
    e=0
    for b in 128 ; do
        for f in ../tests/KAT_SM4/ECB*${b}.rsp ; do
            if ! $exec $b < $f ; then e=$((e+1)) ; echo fail: $b ; fi
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

ret=0
src_common="sm4-test.c 0-datum/endian.c"
bin=$(basename "$0" .sh)

cflags=""
srcset="Plain C"
src="sm4.c"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
