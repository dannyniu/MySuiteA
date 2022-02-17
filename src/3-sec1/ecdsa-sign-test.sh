#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
ecdsa-sign-test.c
ecdsa.c
sec1-keygen.c
2-ec/ecp-xyz.c
2-ec/curve-secp256r1.c
2-ec/curve-secp384r1.c
2-hash/sha.c
1-integers/vlong.c
1-integers/vlong-dat.c
1-symm/fips-180.c
0-datum/endian.c
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
