#!/bin/sh

testfunc() {
    e=0
    for b in 128 192 256 ; do
        for f in ../tests/KAT_ARIA/ECB*${b}.rsp ; do
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
. $unitest_sh

src_common="aria-test.c 0-datum/endian.c"

arch_family=defaults
cflags=""
srcset="Plain C"
src="aria.c"

tests_run
