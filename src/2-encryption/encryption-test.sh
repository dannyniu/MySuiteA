#!/bin/sh

testdir1=../tests/gcm-test-vectors
testdir2=../tests/chacha20-poly1305

testfunc() {
    e=0;

    $exec ChaCha20-Poly1305 $testdir2/vec-01.txt || e=$((e+1))
    $exec ChaCha20-Poly1305 $testdir2/vec-02.txt || e=$((e+1))

    $exec GCM-AES-128 $testdir1/vec-01.txt || e=$((e+1))
    $exec GCM-AES-128 $testdir1/vec-02.txt || e=$((e+1))
    $exec GCM-AES-128 $testdir1/vec-03.txt || e=$((e+1))
    $exec GCM-AES-128 $testdir1/vec-04.txt || e=$((e+1))

    $exec GCM-AES-192 $testdir1/vec-07.txt || e=$((e+1))
    $exec GCM-AES-192 $testdir1/vec-08.txt || e=$((e+1))
    $exec GCM-AES-192 $testdir1/vec-09.txt || e=$((e+1))
    $exec GCM-AES-192 $testdir1/vec-10.txt || e=$((e+1))

    $exec GCM-AES-256 $testdir1/vec-13.txt || e=$((e+1))
    $exec GCM-AES-256 $testdir1/vec-14.txt || e=$((e+1))
    $exec GCM-AES-256 $testdir1/vec-15.txt || e=$((e+1))
    $exec GCM-AES-256 $testdir1/vec-16.txt || e=$((e+1))

    echo "$e test(s) failed."

    if [ $e -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
encryption-test.c
chacha20-poly1305.c
gcm-aes.c
gcm.c
1-symm/chacha.c
1-symm/poly1305.c
0-datum/endian.c
"

. ../1-symm/aes-cipher-variants.sh.inc # rijndael
