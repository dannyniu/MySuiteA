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

. ../1-symm/rijndael-variants.sh.inc
