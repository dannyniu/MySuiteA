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
    kmax=5
    mmax=13
    for algo in $hash_algos ; do
        kcnt=0
        while [ $kcnt -lt $kmax ] ; do
            mcnt=0
            while [ $mcnt -lt $mmax ] ; do
                echo $algo $(($(shortrand) % 64)) $(shortrand)
                mcnt=$((mcnt + 1))
            done
            kcnt=$((kcnt+1))
        done
    done | while
        rm -f mac-test-ref mac-test-result mac-test-key mac-test-data
        if ! read algo klen mlen ; then
            echo "$failcount test(s) failed."
            if [ $failcount -gt 0 ]
            then return 1
            else return 0
            fi
        else true ; fi
    do
        randblob $klen > mac-test-key
        randblob $mlen > mac-test-data

        ../src/2-mac/hmac-test.py $algo < mac-test-data > mac-test-ref &
        $exec $algo < mac-test-data > mac-test-result &
        wait

        if [ "$(cat mac-test-ref)" = "$(cat mac-test-result)" ] ; then
            : echo Test succeeded for $algo klen=$klen mlen=$mlen
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
            failcount=$((failcount+1))
            suffix=$(date +%Y-%m-%d-%H%M%S)-$failcount
            mv mac-test-key mac-test-key-$suffix
            mv mac-test-data mac-test-data-$suffix
        fi
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
hmac-t-test.c
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

arch_family=defaults
srcset="Plain C"

tests_run
