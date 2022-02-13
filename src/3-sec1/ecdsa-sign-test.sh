#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
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
optimize=debug

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
