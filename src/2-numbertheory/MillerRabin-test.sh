#!/bin/sh

testfunc() {
    $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
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

echo ======== Test Name: $bin ========
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
