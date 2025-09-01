#!/bin/sh

optimize=debug
testfunc() {
    $exec xof < ../tests/Ascon/LWC_HASH_KAT_128_256.txt
    ../src/2-hash/ascon-hash-test-json-conv.py \
        < ../tests/Ascon/Ascon-Hash256-SP800-232.json |
        $exec xof || return $?
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
