#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
largeint-test.c
largeint.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
