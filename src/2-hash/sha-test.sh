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
    mcnt=0;
    mmax=17
    while [ $mcnt -lt $mmax ] ; do
        mlen=$(shortrand)
        rm -f $testvec
        randblob $mlen > $testvec

        for b in 1 224 256 384 512 ; do
            ../src/2-hash/shasum.py sha$b < $testvec > hash-ref.dat &
            $exec xSHA$b < $testvec > hash-res.dat &
            $exec iSHA$b < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha${b} failed with $ref:$res:$ret
                n=$((n+1))
                datetime=$(date +%Y-%m-%d-%H%M%S)
                cp $testvec failed-sha${b}-$mlen.$datetime.$arch.dat
            fi
            rm hash-re[fst].dat
        done

        for b in 224 256; do
            ../src/2-hash/shasum.py sha512_$b < $testvec > hash-ref.dat &
            $exec xSHA512t${b} < $testvec > hash-res.dat &
            $exec iSHA512t${b} < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha512-${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-sha512t-${b}-$mlen.$datetime.$arch.dat
            fi
            rm hash-re[fst].dat
        done

        unlink $testvec
        mcnt=$((mcnt + 1))
    done

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
sha-test.c
sha.c
0-datum/endian.c
"

arch_family=defaults
src="1-symm/fips-180.c"
srcset="Plain C"

tests_run

arch_family=x86 # AMD CPUs Only for now.
cflags="-msha -mssse3 -D TEST_WITH_MOCK -D NI_FIPS180=NI_ALWAYS"
src="1-symm/fips-180-x86.c"
srcset="x86 SHA Extensions"

tests_run

arch_family=arm # Apple Silicons Only for now.
cflags="-march=armv8-a+crypto+sha3 -D NI_FIPS180=NI_ALWAYS"
src="1-symm/fips-180-arm.c"
srcset="ARMv8 Crypto Extensions"

if [ "$(uname -sm)" = "Darwin arm64" ] ; then tests_run ; fi
