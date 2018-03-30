#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
keccak-test.c
keccak-f-1600.c
0-datum/endian.c
"
bin=keccak-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
