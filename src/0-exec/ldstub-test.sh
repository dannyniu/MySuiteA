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
. $unitest_sh

src="\
ldstub.c
"

arch_family=defaults
srcset="Plain C"

tests_run
