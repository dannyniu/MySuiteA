#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-numbertheory/EGCD-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
EGCD-test.c
EGCD.c
1-integers/vlong.c
"

arch_family=defaults
srcset="Plain C"

tests_run
