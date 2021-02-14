#!/bin/sh

# [2021-01-10]:
# It's noticed that, some user-space qemu emulator has unexpected
# segfault problems. The sole purpose of this test is to verify that,
# qemu user-space emulator programs are functioning correctly.

testfunc() {
    $exec ../tests/rsa-1440-3primes.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsa-der-parse-test.c
rsa.c
2-asn1/der-parse.c
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
