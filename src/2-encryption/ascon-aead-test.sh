#!/bin/sh

testfunc() {
    e=0
    $exec ../tests/Ascon/LWC_AEAD_KAT_128_128.txt || e=$((e+1))
    echo "$e test(s) failed."

    if [ $e -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ascon-aead-test.c
ascon-aead.c
1-symm/ascon-permutation.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
