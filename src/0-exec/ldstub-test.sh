#!/bin/sh

# [2021-01-10]:
# It's noticed that, some user-space qemu emulator has unexpected
# segfault problems. The sole purpose of this test is to verify
# whether qemu user-space emulator programs are functioning correctly.

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
ldstub.c
"

bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
