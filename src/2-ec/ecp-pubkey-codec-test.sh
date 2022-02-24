#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ecp-pubkey-codec-test.c
ecp-pubkey-codec.c
ecp-xyz.c
curve-secp256r1.c
curve-secp384r1.c
1-integers/vlong.c
1-integers/vlong-dat.c
"

arch_family=defaults
srcset="Plain C"

tests_run
