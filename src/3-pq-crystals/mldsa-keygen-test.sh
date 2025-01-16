#!/bin/sh

optimize=debug
testfunc() {
    ../src/3-pq-crystals/mldsa-keygen-test.py $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
mldsa-keygen-test.c
mldsa-paramset.c
mldsa.c
2-pq-crystals/dilithium-aux.c
2-hash/hash-dgst-oid-table.c
2-hash/sha.c
2-xof/shake.c
1-pq-crystals/m256-codec.c
1-symm/keccak-f-1600.c
1-symm/fips-180.c
1-symm/sponge.c
0-datum/endian.c
./mysuitea-common.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

srcset="Plain C"
tests_run
