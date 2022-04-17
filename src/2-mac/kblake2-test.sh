#!/bin/sh

if ! command -v python3 >/dev/null ; then
    echo "Cannot invoke python3. (Not installed?)"
    exit 1
elif [ $(expr "$(python3 --version 2>&1)" '>=' "Python 3.6") != 1 ] ; then
    echo "Python version too old, (3.6 or newer required)" # Assumes CPython.
    exit 1;
fi

hash_algos="
blake2b-160
blake2b-256
blake2b-384
blake2b-512
blake2s-128
blake2s-160
blake2s-224
blake2s-256
"

testfunc() {
    failcount=0
    kmax=5
    mmax=13
    for algo in $hash_algos ; do
        kcnt=0
        variant=${algo%-*}
        outlen=${algo#*-}
        while [ $kcnt -lt $kmax ] ; do
            mcnt=0
            while [ $mcnt -lt $mmax ] ; do
                if [ $variant = blake2b ]
                then klen=$(($(shortrand) % 64))
                else klen=$(($(shortrand) % 32))
                fi
                echo $variant $outlen $klen $(shortrand)
                mcnt=$((mcnt + 1))
            done
            kcnt=$((kcnt+1))
        done
    done | while
        rm -f mac-test-ref mac-test-result mac-test-key mac-test-data
        if ! read variant outlen klen mlen ; then
            echo "$failcount test(s) failed."
            if [ $failcount -gt 0 ]
            then return 1
            else return 0
            fi
        else true ; fi
    do
        algo=${variant}${outlen}

        randblob $klen > mac-test-key
        randblob $mlen > mac-test-data

        ../src/2-mac/kblake2-test.py \
            $variant $outlen \
            < mac-test-data > mac-test-ref &
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
kblake2-test.c
2-hash/blake2.c
1-symm/chacha.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
