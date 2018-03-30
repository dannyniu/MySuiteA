#!/bin/sh

testfunc() {
    for b in 128 192 256 ; do
        for f in ../../tests/KAT_AES/ECB*${b}.rsp ; do
            $exec $b < $f
            echo "${bin##*/} $b < ${f##*/}: Exited: $?"
        done
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="aes-test.c 0-datum/endian.c"
bin=aes-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
src="$src_common rijndael.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
src="$src_common rijndael.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
src="$src_common rijndael.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
src="$src_common rijndael.c"
( . $unitest_sh )

echo ================================================================
echo x86 AESNI intrinsics.
arch=x86_64 cflags="-maes"
src="$src_common rijndael-x86.c"
( . $unitest_sh )

echo ================================================================
echo ARM NEON Crypto intrinsics.
arch=aarch64 cflags="-march=armv8-a+crypto"
src="$src_common rijndael-arm.c"
( . $unitest_sh )
