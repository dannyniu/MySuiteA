#!/bin/sh

testfunc() {
    $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ecMt-point-scl-check.c
ecMt.c
ec-common.c
curve25519.c
modp25519.c
1-integers/vlong-dat.c
1-integers/vlong.c
"

arch_family=defaults
srcset="Plain C"

tests_run
