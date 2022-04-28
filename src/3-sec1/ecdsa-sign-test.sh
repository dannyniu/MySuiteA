#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
ecdsa-sign-test.c
ecdsa.c
3-ecc-common/ecc-common.c
2-ec/ec-common.c
2-ec/ecp-xyz.c
2-ec/ecp-pubkey-codec.c
2-ec/curve-secp256r1.c
2-ec/curve-secp384r1.c
2-hash/sha.c
2-asn1/der-codec.c
1-integers/vlong.c
1-integers/vlong-dat.c
1-symm/fips-180.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
