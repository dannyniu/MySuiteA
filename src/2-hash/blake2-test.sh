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
    mcnt=0
    mmax=17
    while [ $mcnt -lt $mmax ] ; do
        mlen=$(shortrand)
        rm -f $testvec
        randblob $mlen > $testvec

        for b in 160 256 384 512 ; do
            ../src/2-hash/b2sum.py blake2b $b < $testvec > hash-ref.dat &
            $exec xBLAKE2b$b < $testvec > hash-res.dat &
            $exec iBLAKE2b$b < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo BLAKE2b${b} failed with "$ref" != $res
                n=$((n+1))
                cp $testvec failed-blake2b${b}-$mlen.$arch.dat
            fi
            rm hash-re[fst].dat
        done

        for b in 128 160 224 256 ; do
            ../src/2-hash/b2sum.py blake2s $b < $testvec > hash-ref.dat &
            $exec xBLAKE2s$b < $testvec > hash-res.dat &
            $exec iBLAKE2s$b < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo BLAKE2s${b} failed with "$ref" != $res
                n=$((n+1))
                cp $testvec failed-blake2s${b}-$mlen.$arch.dat
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

src="\
blake2-test.c
blake2.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
