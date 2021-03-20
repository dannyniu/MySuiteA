#!/bin/sh

# [2021-01-10]:
# It's noticed that, some user-space qemu emulator has unexpected
# segfault problems. The sole purpose of this test is to verify that,
# qemu user-space emulator programs are functioning correctly.

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
ldstub.c
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
