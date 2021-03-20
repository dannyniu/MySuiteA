#!/bin/sh

cat << EOF
# 2020-12-06, == Test Conclusions ==
# This test is based on the example file "CTR_DRBG_withDF.pdf". 
# from NIST CSRC website. I had debugged thoroughly and made sure 
# each and every individual routines are correct, however the 
# example file contain numerous errors and inconsistencies, and
# I was not able to reproduce the results from the example file.
# Testing of CTR-DRBG with derivation function had therefore been
# forsaken.
EOF

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="
ctr-drbg-aes-df-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

vsrc(){ src="$src_common 1-symm/rijndael${1}.c" ; }

arch=x86_64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=aarch64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=powerpc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=sparc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=x86_64 cflags="-maes" srcset="AESNI"
vsrc "-x86"
( . $unitest_sh )

arch=aarch64 cflags="-march=armv8-a+crypto" srcset="ARM NEON Crypto"
vsrc "-arm"
( . $unitest_sh )
