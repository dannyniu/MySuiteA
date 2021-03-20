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
