#!/bin/sh

if ! command -v python3 >/dev/null ; then
    echo "Cannot invoke python3. (Not installed?)"
    exit 1
elif [ $(expr "$(python3 --version 2>&1)" '>=' "Python 3.6") != 1 ] ; then
    echo "Python version too old, (3.6 or newer required)" # Assumes CPython. 
    exit 1;
fi

hash_algos="
sha1
sha224
sha256
sha384
sha512
sha3_224
sha3_256
sha3_384
sha3_512
"

testfunc() {
    failcount=0
    for algo in $hash_algos ; do
        klen=0
        while [ $klen -lt 288 ] ; do
            mlen=0
            while [ $mlen -lt 32768 ] ; do
                echo $algo $klen $mlen
                mlen=$((mlen*3+251))
            done
            klen=$((klen*3+7))
        done 
    done | while
        if ! read algo klen mlen ; then
            echo $failcount tests failed.
            false
        fi
    do
        dd if=/dev/urandom bs=1 count=$klen \
           of=mac-test-key 2>/dev/null

        dd if=/dev/urandom bs=1 count=$mlen \
           of=mac-test-data 2>/dev/null

        ../src/2-mac/hmac-test.py $algo < mac-test-data > hmac-test-ref &
        $exec $algo < mac-test-data > hmac-test-result &
        wait
        
        if [ "$(cat hmac-test-ref)" = "$(cat hmac-test-result)" ] ; then
            : echo Test succeeded for $algo klen=$klen mlen=$mlen
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
            failcount=$((failcount+1))
            suffix=$(date +%Y-%m-%d-%H%M%S)-$failcount
            mv mac-test-key hmac-test-key-$suffix
            mv mac-test-data hmac-test-data-$suffix
        fi
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
hmac-test.c
hmac-sha.c
hmac-sha3.c
hmac.c
2-hash/sha.c
2-hash/sha3.c
1-symm/fips-180.c
1-symm/sponge.c
1-symm/keccak-f-1600.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

echo ======== Test Name: $bin ========
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ======== Test Name: $bin ========
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
