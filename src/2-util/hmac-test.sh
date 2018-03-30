#!/bin/sh

hash_algos="
sha1
sha224
sha256
sha384
sha512
sha3-224
sha3-256
sha3-384
sha3-512
"

testfunc() {
    for algo in $hash_algos ; do
        klen=0
        while [ $klen -lt 1024 ] ; do
            mlen=0
            while [ $mlen -lt 1000000 ] ; do
                echo $algo $klen $mlen
                mlen=$((mlen*2+100))
            done
            klen=$((klen*2+8))
        done 
    done | while read algo klen mlen ; do
        
        dd if=/dev/urandom bs=4 count=$((klen/4)) \
           of=hmac-test-key 2>/dev/null

        dd if=/dev/urandom bs=100 count=$((mlen/100)) \
           of=hmac-test-data 2>/dev/null

        if [ $(../src/2-util/hmac-test.php $algo) = $($exec $algo) ] ; then
            echo Test succeeded for $algo klen=$klen mlen=$mlen >&2
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
        fi
    done | echo $(awk 'END { print NR; }') tests failed.
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
../src/2-util/hmac-test.c
../src/2-util/hmac-sha.c
../src/2-util/hmac.c
../src/2-hash/sha.c
../src/2-hash/sha3.c
../src/1-symm/fips-180.c
../src/1-symm/sponge.c
../src/1-symm/keccak-f-1600.c
../src/0-datum/endian.c
"
bin=hmac-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
