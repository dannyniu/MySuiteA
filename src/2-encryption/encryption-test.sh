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
bin=$(basename "$0" .sh)

testdir1=../tests/gcm-test-vectors
testdir2=../tests/chacha20-poly1305

vsrc(){ src="$src_common 1-symm/rijndael${1}.c 1-symm/galois128${1}.c" ; }

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

arch=x86_64 cflags="-maes -mpclmul" srcset="x86 AESNI+PCLMUL"
vsrc "-x86"
( . $unitest_sh )

arch=aarch64 cflags="-march=armv8-a+crypto" srcset="ARM NEON Crypto"
vsrc "-arm"
( . $unitest_sh )
