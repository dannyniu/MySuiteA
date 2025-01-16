#!/bin/sh

cat <<EOF
2024-10-09:
There was a formula error in "slhdsa.h" header that was corrected. Previously
assumed failure reason of large stack objects was in fact a buffer overflow
error. Now the tests should pass.
EOF

optimize=true
testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
slhdsa-self-fed-test.c
slhdsa.c
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
2-mac/hmac-sha.c
2-mac/hmac.c
2-xof/shake.c
2-xof/gimli-xof.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/fips-180.c
1-symm/sponge.c
0-datum/endian.c
./mysuitea-common.c
"

arch_family=defaults

cflags_common=""
srcset_common="Pre-Hashing"
. ./slhdsa-srcsets.sh.inc

cflags_common="-D PKC_DSS_No_Incremental_Tests"
srcset_common="Buffered"
. ./slhdsa-srcsets.sh.inc
