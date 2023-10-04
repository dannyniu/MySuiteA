#!/bin/sh

optimize=debug
testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
mldsa-self-fed-test.c
mldsa.c
2-pq-crystals/dilithium-aux.c
2-xof/shake.c
2-xof/gimli-xof.c
1-pq-crystals/m256-codec.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

cflags="-D LatticeK=4 -D LatticeL=4"
srcset="MLDSA-44"
tests_run

cflags="-D LatticeK=6 -D LatticeL=5"
srcset="MLDSA-65"
tests_run

cflags="-D LatticeK=8 -D LatticeL=7"
srcset="MLDSA-87"
tests_run
