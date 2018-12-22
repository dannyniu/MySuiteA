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
                mlen=$((mlen*3+251))
            done
            klen=$((klen*3+61))
        done 
    done | while read algo klen mlen ; do
        
        dd if=/dev/urandom bs=1 count=$klen \
           of=hmac-test-key 2>/dev/null

        dd if=/dev/urandom bs=1 count=$mlen \
           of=hmac-test-data 2>/dev/null

        ../src/2-mac/hmac-test.php $algo > hmac-test-ref &
        $exec $algo > hmac-test-result &
        wait
        
        if [ $(cat hmac-test-ref) = $(cat hmac-test-result) ] ; then
            echo Test succeeded for $algo klen=$klen mlen=$mlen >&2
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
        fi
    done | echo $(awk 'END { print NR; }') tests failed.
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
hmac-test.c
hmac-sha.c
hmac.c
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
