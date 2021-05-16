#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-numbertheory/EGCD-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
EGCD-test.c
EGCD.c
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
