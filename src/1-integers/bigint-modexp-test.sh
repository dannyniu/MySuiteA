#!/bin/sh

testfunc() {
    $exec < /dev/urandom | bc $basedir/bigint-misc-test.bc
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
bigint-modexp-test.c
bigint.c
bignum.c
"
bin=bigint-egcd-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )
