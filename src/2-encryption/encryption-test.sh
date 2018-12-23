#!/bin/sh

testfunc() {
    $exec 20 $testdir2/vec-01.txt
    $exec 20 $testdir2/vec-02.txt
    
    $exec 128 $testdir1/vec-01.txt
    $exec 128 $testdir1/vec-02.txt
    $exec 128 $testdir1/vec-03.txt
    $exec 128 $testdir1/vec-04.txt

    $exec 192 $testdir1/vec-07.txt
    $exec 192 $testdir1/vec-08.txt
    $exec 192 $testdir1/vec-09.txt
    $exec 192 $testdir1/vec-10.txt

    $exec 256 $testdir1/vec-13.txt
    $exec 256 $testdir1/vec-14.txt
    $exec 256 $testdir1/vec-15.txt
    $exec 256 $testdir1/vec-16.txt
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="
encryption-test.c
chacha20-poly1305.c
gcm-aes.c
gcm.c
1-symm/chacha.c
1-symm/poly1305.c
0-datum/endian.c
"
bin=encryption-test

testdir1=../../tests/gcm-test-vectors
testdir2=../../tests/chacha20-poly1305

vsrc(){ src="$src_common 1-symm/rijndael${1}.c 1-symm/galois128${1}.c" ; }

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
vsrc ""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
vsrc ""
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
vsrc ""
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
vsrc ""
( . $unitest_sh )

echo ================================================================
echo x86 AESNI + PCLMUL intrinsics.
arch=x86_64 cflags="-maes -mpclmul"
vsrc "-x86"
( . $unitest_sh )

echo ================================================================
echo ARM NEON Crypto intrinsics.
arch=aarch64 cflags="-march=armv8-a+crypto"
vsrc "-arm"
( . $unitest_sh )
