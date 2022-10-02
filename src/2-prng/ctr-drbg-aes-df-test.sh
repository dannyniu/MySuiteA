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

arch_family=defaults
cflags=""
srcset="Plain C"
src="1-symm/rijndael.c"

tests_run

arch_family=x86
cflags="-maes -D NI_AES=NI_ALWAYS"
srcset="x86 AESNI"
src="1-symm/rijndael-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto -D NI_AES=NI_ALWAYS"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"

tests_run

arch_family=ppc
cflags="-mcpu=power8 -D NI_AES=NI_ALWAYS"
srcset="PowerPC AltiVec Crypto"
src="1-symm/rijndael-ppc.c"

tests_run
