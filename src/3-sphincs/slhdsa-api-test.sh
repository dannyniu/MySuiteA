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
slhdsa-api-test.c
slhdsa.c
sphincs-subroutines-wots.c
sphincs-subroutines-xmss.c
sphincs-subroutines-fors.c
sphincs-subroutines-hypertree.c
sphincs-hash-params-family-sha256.c
sphincs-hash-params-family-sha512.c
sphincs-hash-params-family-sha2-common.c
2-hash/sha.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-xof/shake.c
2-xof/gimli-xof.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/fips-180.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

cflags="-D HashN=16 -D HashH=63"
srcset="SLH-DSA-128s"
tests_run
