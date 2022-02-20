#!/bin/sh

optimize=true
testfunc() {
    time $exec "$(date)"
    #xcrun xctrace record --launch -- $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
MillerRabin-test.c
MillerRabin.c
1-integers/vlong.c
2-xof/gimli-xof.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
