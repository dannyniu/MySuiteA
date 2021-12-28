#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-ec/secp-point-arith-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
secp-point-add-test.c
secp-xyz.c
1-integers/vlong.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64 cflags=""-DENABLE_HOSTED_HEADERS=
( . $unitest_sh )

arch=aarch64 cflags=""-DENABLE_HOSTED_HEADERS=
( . $unitest_sh )

arch=powerpc64 cflags=""-DENABLE_HOSTED_HEADERS=
( . $unitest_sh )

arch=sparc64 cflags=""-DENABLE_HOSTED_HEADERS=
( . $unitest_sh )
