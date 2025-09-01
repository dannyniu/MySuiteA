#!/bin/sh

optimize=debug
testfunc() {
    $exec  xof < ../tests/Ascon/LWC_\XOF_KAT_128_512.txt || return $?
    $exec cxof < ../tests/Ascon/LWC_CXOF_KAT_128_512.txt || return $?
    ../src/2-hash/ascon-hash-test-json-conv.py \
        < ../tests/Ascon/Ascon-XOF128-SP800-232.json |
        $exec xof || return $?
    ../src/2-xof/ascon-cxof-test-json-conv.py \
        < ../tests/Ascon/Ascon-CXOF128-SP800-232.json |
        $exec cxof || return $?
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ascon-xof-test.c
ascon-xof.c
1-symm/ascon-permutation.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
