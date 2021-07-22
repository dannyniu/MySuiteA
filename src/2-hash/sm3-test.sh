#!/bin/sh

testfunc() {
    rm -f failed-*.dat success-*.dat
    n=0
    testvec=testblob.dat

    printf "abc" > $testvec
    mlen=3
    ref=66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    res=$($exec < $testvec)
    if ! [ "$ref" = "$res" ] ; then
        echo SM3 failed with "$ref" != $res
        n=$((n+1))
        datetime=$(date +%Y-%m-%d-%H%M%S)
        cp $testvec failed-sm3-$mlen.$datetime.$arch.dat
    fi

    for x in 1 2 3 4
    do for y in 1 2 3 4 ; do printf "abcd" ; done ; done > $testvec
    mlen=64
    ref=debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
    res=$($exec < $testvec)
    if ! [ "$ref" = "$res" ] ; then
        echo SM3 failed with "$ref" != $res
        n=$((n+1))
        datetime=$(date +%Y-%m-%d-%H%M%S)
        cp $testvec failed-sm3-$mlen.$datetime.$arch.dat
    fi

    printf "%u failed tests.\n" $n
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
sm3-test.c
sm3.c
1-symm-national/gbt-32905.c
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
