#!/bin/sh

if ! command -v python3 >/dev/null ; then
    echo "Cannot invoke python3. (Not installed?)"
    exit 1;
elif [ $(expr "$(python3 --version 2>&1)" '>=' "Python 3.6") != 1 ] ; then
    echo "Python version too old, (3.6 or newer required)" # Assumes CPython. 
    exit 1;
fi

testfunc() {
    rm -f failed-*.dat success-*.dat
    n=0
    testvec=testblob.dat
    mlen=0;
    while [ $mlen -lt 1000000 ] ; do
        dd if=/dev/urandom bs=32 count=$((mlen/32)) of=$testvec 2>/dev/null
        
        for b in 160 256 384 512 ; do
            ref=$(../src/2-hash/b2sum.py blake2b $b < $testvec)
            res=$($exec blake2b$b < $testvec)
            if ! [ "${ref%%[!a-zA-Z0-9]*}" = $res ] ; then
                echo BLAKE2b${b} failed with "$ref" != $res
                n=$((n+1))
                cp $testvec failed-blake2b${b}-$mlen.$arch.dat
            fi
        done
        
        for b in 128 160 224 256 ; do
            ref=$(../src/2-hash/b2sum.py blake2s $b < $testvec)
            res=$($exec blake2s$b < $testvec)
            if ! [ "${ref%%[!a-zA-Z0-9]*}" = $res ] ; then
                echo BLAKE2s${b} failed with "$ref" != $res
                n=$((n+1))
                cp $testvec failed-blake2s${b}-$mlen.$arch.dat
            fi
        done

        unlink $testvec
        mlen=$((mlen*2+32))
    done
    printf "%u failed tests.\n" $n
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
blake2-test.c
blake2.c
1-symm/chacha.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
