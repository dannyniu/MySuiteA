#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
kmac-test.c
kmac.c
2-xof/shake.c
1-symm/sponge.c
1-symm/keccak-f-1600.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
