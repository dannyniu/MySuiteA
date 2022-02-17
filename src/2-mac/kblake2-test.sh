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
    for algo in $hash_algos ; do
        klen=0
        variant=${algo%-*}
        outlen=${algo#*-}
        while
            if [ $variant = blake2b ]
            then [ $klen -lt 64 ]
            else [ $klen -lt 32 ]
            fi
        do
            mlen=0
            while [ $mlen -lt 32768 ] ; do
                echo $variant $outlen $klen $mlen
                mlen=$((mlen*3+251))
            done
            klen=$((klen*2+3))
        done 
    done | while
        if ! read variant outlen klen mlen ; then
            echo "$failcount test(s) failed."
            if [ $failcount -gt 0 ]
            then return 1
            else return 0
            fi
        else true ; fi
    do
        algo=${variant}${outlen}
        
        dd if=/dev/urandom bs=1 count=$klen \
           of=mac-test-key 2>/dev/null

        dd if=/dev/urandom bs=1 count=$mlen \
           of=mac-test-data 2>/dev/null

        ../src/2-mac/kblake2-test.py \
            $variant $outlen \
            < mac-test-data > kblake2-test-ref &
        $exec $algo < mac-test-data > kblake2-test-result &
        wait
        
        if [ "$(cat kblake2-test-ref)" = "$(cat kblake2-test-result)" ] ; then
            : echo Test succeeded for $algo klen=$klen mlen=$mlen
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
            failcount=$((failcount+1))
            suffix=$(date +%Y-%m-%d-%H%M%S)-$failcount
            mv kblake2-test-key kblake2-test-key-$suffix
            mv kblake2-test-data kblake2-test-data-$suffix
        fi
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
kblake2-test.c
2-hash/blake2.c
1-symm/chacha.c
0-datum/endian.c
"

bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
