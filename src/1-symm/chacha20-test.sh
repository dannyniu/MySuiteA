#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
chacha20-test.c
chacha20.c
0-datum/endian.c
"
bin=aes-test

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
