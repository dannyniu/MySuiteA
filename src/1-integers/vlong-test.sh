#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="
vlong-test.c
vlong.c
"
srcset="Plain C"
ldflags="-lgcc -lgcc_s"

arch_family=+aarch64
tests_run

arch_family=+powerpc64
tests_run

arch_family=+riscv64
tests_run

arch_family=+x86_64
tests_run
