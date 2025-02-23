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
mlkem-self-fed-test.c
mlkem.c
2-pq-crystals/kyber-aux.c
2-xof/shake.c
2-xof/gimli-xof.c
2-hash/sha3.c
1-pq-crystals/m256-codec.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

cflags="-D LatticeK=2"
srcset="MLKEM-512"
tests_run

cflags="-D LatticeK=3"
srcset="MLKEM-768"
tests_run

cflags="-D LatticeK=4"
srcset="MLKEM-1024"
tests_run
