#!/bin/sh

optimize=debug
testfunc() {
    ../src/3-pq-crystals/mlkem-keygen-test.py $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
mlkem-keygen-test.c
mlkem-paramset.c
mlkem.c
2-pq-crystals/kyber-aux.c
2-xof/shake.c
2-hash/sha3.c
1-pq-crystals/m256-codec.c
1-symm/keccak-f-1600.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

srcset="Plain C"
tests_run
