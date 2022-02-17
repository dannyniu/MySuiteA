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

        for b in 1 224 256 384 512 ; do
            ref=$(../src/2-hash/shasum.py sha$b < $testvec)
            res=$($exec xSHA$b < $testvec)
            ret=$($exec iSHA$b < $testvec)
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha${b} failed with $ref:$res:$ret
                n=$((n+1))
                datetime=$(date +%Y-%m-%d-%H%M%S)
                cp $testvec failed-sha${b}-$mlen.$datetime.$arch.dat
            fi
        done

        for b in 224 256; do
            ref=$(../src/2-hash/shasum.py sha512_$b < $testvec)
            res=$($exec xSHA512t${b} < $testvec)
            ret=$($exec iSHA512t${b} < $testvec)
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha512-${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-sha512t-${b}-$mlen.$datetime.$arch.dat
            fi
        done

        for b in 224 256 384 512; do
            ref=$(../src/2-hash/shasum.py sha3_$b < $testvec)
            res=$($exec xSHA3_$b < $testvec)
            ret=$($exec iSHA3_$b < $testvec)
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha3-${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-sha3-${b}-$mlen.$datetime.$arch.dat
            fi
        done

        for b in 128 256; do
            ref=$(../src/2-hash/shakesum.py shake_$b < $testvec)
            res=$($exec xSHA3_${b}000 < $testvec)
            ret=$($exec iSHA3_${b}000 < $testvec)
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo shake${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-shake-${b}-$mlen.$datetime.$arch.dat
            fi
        done

        unlink $testvec
        mlen=$((mlen*2+32))
    done
    
    printf "%u failed tests.\n" $n
    if [ $n -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
sha-test.c
sha.c
sha3.c
2-xof/shake.c
1-symm/fips-180.c
1-symm/sponge.c
1-symm/keccak-f-1600.c
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
