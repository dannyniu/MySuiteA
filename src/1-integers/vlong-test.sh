#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="
vlong-test.c
vlong.c
"

arch_family=defaults
srcset="Plain C"

tests_run
