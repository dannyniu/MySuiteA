#!/bin/sh

optimize=true
testfunc() {
    ../src/3-sphincs/slhdsa-siggen-test.py $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
slhdsa-siggen-test.c
sphincs-subroutines-wots.c
sphincs-subroutines-xmss.c
sphincs-subroutines-fors.c
sphincs-subroutines-hypertree.c
sphincs-hash-params-family-sha256.c
sphincs-hash-params-family-sha512.c
sphincs-hash-params-family-sha2-common.c
sphincs-hash-params-family-shake.c
2-hash/hash-dgst-oid-table.c
2-hash/sha.c
2-hash/sha3.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-xof/shake.c
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
