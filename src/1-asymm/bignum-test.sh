#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
bignum-test.c
bignum.c
"
bin=bigint-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )
