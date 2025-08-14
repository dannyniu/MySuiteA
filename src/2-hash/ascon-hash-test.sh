#!/bin/sh

optimize=debug
testfunc() {
    $exec xof < ../tests/Ascon/LWC_HASH_KAT_128_256.txt
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ascon-hash-test.c
ascon-hash.c
1-symm/ascon-permutation.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
