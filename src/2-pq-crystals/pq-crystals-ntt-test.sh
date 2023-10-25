#!/bin/sh

optimize=debug
testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
pq-crystals-ntt-test.c
dilithium-aux.c
kyber-aux.c
1-pq-crystals/m256-codec.c
2-xof/shake.c
1-symm/keccak-f-1600.c
1-symm/sponge.c
0-datum/endian.c
"

cflags_common="-D ENABLE_HOSTED_HEADERS="

arch_family=defaults
cflags="-D MLAlgo=MLKEM"
srcset="NTT: ML-KEM / Kyber"

tests_run

arch_family=defaults
cflags="-D MLAlgo=MLDSA"
srcset="NTT: ML-DSA / Dilithium"

tests_run
