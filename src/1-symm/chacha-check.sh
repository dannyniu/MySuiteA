#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
chacha-check.c
chacha.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
