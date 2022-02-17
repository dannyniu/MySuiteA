#!/bin/sh

testfunc() {
    $exec < /dev/urandom | ../src/2-numbertheory/EGCD-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
EGCD-test.c
EGCD.c
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
