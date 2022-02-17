#!/bin/sh

testfunc() {
    time $exec "$(date)"
    #xcrun xctrace record --launch -- $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
MillerRabin-test.c
MillerRabin.c
1-integers/vlong.c
2-xof/gimli-xof.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

bin=$(basename "$0" .sh)
srcset="Plain C"
optimize=true

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
