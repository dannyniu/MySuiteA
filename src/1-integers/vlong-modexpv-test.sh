#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/1-integers/vlong-modexpv-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
vlong-modexpv-test.c
vlong.c
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
