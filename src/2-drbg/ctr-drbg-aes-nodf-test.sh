#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="
ctr-drbg-aes-nodf-test.c
ctr-drbg-aes.c
ctr-drbg.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

vsrc(){ src="$src_common 1-symm/rijndael${1}.c" ; }

echo ======== Test Name: $bin ========
echo C language code. [x86_64]
arch=x86_64 cflags="-D CTR_DRBG_OMIT_DF"
vsrc ""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [aarch64]
arch=aarch64 cflags="-D CTR_DRBG_OMIT_DF"
vsrc ""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [powerpc64]
arch=powerpc64 cflags="-D CTR_DRBG_OMIT_DF"
vsrc ""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [sparc64]
arch=sparc64 cflags="-D CTR_DRBG_OMIT_DF"
vsrc ""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo x86 AESNI intrinsics.
arch=x86_64 cflags="-D CTR_DRBG_OMIT_DF -maes"
vsrc "-x86"
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo ARM NEON Crypto intrinsics.
arch=aarch64 cflags="-D CTR_DRBG_OMIT_DF -march=armv8-a+crypto"
vsrc "-arm"
( . $unitest_sh )
