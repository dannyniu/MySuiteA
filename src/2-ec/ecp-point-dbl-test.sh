#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-ec/ecp-point-arith-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
ecp-point-dbl-test.c
ecp-xyz.c
curve-secp256r1.c
curve-secp384r1.c
1-integers/vlong.c
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
