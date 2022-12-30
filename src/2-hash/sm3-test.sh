#!/bin/sh

testfunc() {
    rm -f failed-*.dat success-*.dat
    n=0
    testvec=testblob.dat

    exec1="$exec"
    if [ "$srcset" = "ARMv8.4-A Crypto Extensions" ] && [ $arch = $sysarch ]
    then exec1="qemu-aarch64 $exec" ; fi

    rm -f $testvec
    printf "abc" > $testvec
    mlen=3
    ref=66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    res=$($exec1 xSM3 < $testvec)
    ret=$($exec1 iSM3 < $testvec)
    if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
        echo SM3 failed with "$ref" != $res
        n=$((n+1))
        datetime=$(date +%Y-%m-%d-%H%M%S)
        cp $testvec failed-sm3-$mlen.$datetime.$arch.dat
    fi

    rm -f $testvec
    for x in 1 2 3 4
    do for y in 1 2 3 4 ; do printf "abcd" ; done ; done > $testvec
    mlen=4
    ref=debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
    res=$($exec1 xSM3 < $testvec)
    ret=$($exec1 iSM3 < $testvec)
    if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
        echo SM3 failed with "$ref" != $res
        n=$((n+1))
        datetime=$(date +%Y-%m-%d-%H%M%S)
        cp $testvec failed-sm3-$mlen.$datetime.$arch.dat
    fi

    printf "%u failed tests.\n" $n
    if [ $n -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
sm3-test.c
sm3.c
0-datum/endian.c
"

arch_family=defaults
cflags=""
src="1-symm-national/gbt-32905.c"
srcset="Plain C"

tests_run

arch_family=arm
cflags="-march=armv8.2-a+crypto+sm4 -D NI_SM3=NI_ALWAYS"
src="1-symm-national/gbt-32905-arm.c"
srcset="ARMv8.4-A Crypto Extensions"

tests_run
