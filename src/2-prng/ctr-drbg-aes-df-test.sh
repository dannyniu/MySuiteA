#!/bin/sh

: old notes no longer correct << EOF
# 2020-12-06, == Test Conclusions ==
# This test is based on the example file "CTR_DRBG_withDF.pdf".
# from NIST CSRC website. I had debugged thoroughly and made sure
# each and every individual routines are correct, however the
# example file contain numerous errors and inconsistencies, and
# I was not able to reproduce the results from the example file.
# Testing of CTR-DRBG with derivation function had therefore been
# forsaken.
EOF

cat << EOF
# 2021-09-13, == I fixed my own bug ==
# Turns out, there were hard to spot bugs in my code.
# tests run correctly now.
EOF

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ctr-drbg-aes-df-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"

. ../1-symm/rijndael-variants.sh.inc
