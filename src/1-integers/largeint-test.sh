#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
largeint-test.c
largeint.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
