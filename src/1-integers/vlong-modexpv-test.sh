#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/1-integers/vlong-modexpv-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
vlong-modexpv-test.c
vlong.c
"

arch_family=defaults
srcset="Plain C"

tests_run
