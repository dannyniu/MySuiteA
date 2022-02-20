#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
gimli-xof-test.c
gimli-xof.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
