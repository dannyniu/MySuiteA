#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ber-splice-insert-test.c
der-codec.c
"

arch_family=defaults
srcset="Plain C"

tests_run
