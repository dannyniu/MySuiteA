#!/bin/sh

optimize=true
testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
eddsa-check.c
eddsa.c
eddsa-misc.c
2-ec/ec-common.c
2-ec/ecEd.c
2-ec/curve-Ed25519.c
2-ec/curve-Ed448.c
2-ec/modp25519.c
2-ec/modp448.c
2-hash/sha.c
2-hash/sha3.c
1-integers/vlong.c
1-integers/vlong-dat.c
2-xof/shake.c
2-xof/gimli-xof.c
1-symm/fips-180.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
