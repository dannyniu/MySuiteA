#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-ec/ecp-point-arith-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
ecp-point-scl-test.c
ecp-xyz.c
curve-secp256r1.c
curve-secp384r1.c
1-integers/vlong.c
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
