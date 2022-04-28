#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-ec/ec-remv-inplace-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ec-remv-inplace-test.c
ec-common.c
ecp-xyz.c
curve-secp256r1.c
curve-secp384r1.c
modp25519.c
modp448.c
1-integers/vlong.c
"

arch_family=defaults
srcset="Plain C"

tests_run
