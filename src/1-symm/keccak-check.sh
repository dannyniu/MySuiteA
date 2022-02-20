#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
keccak-check.c
keccak-f-1600.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
