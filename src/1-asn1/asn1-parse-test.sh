#!/bin/sh

testfunc() {
    $exec < ../../tests/asn1/noise.der #cloudflare.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="asn1-parse-test.c asn1.c"
bin=asn1-parse-test

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
