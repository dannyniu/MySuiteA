#!/bin/sh

if ! command -v python3 >/dev/null ; then
    echo "Cannot invoke python3. (Not installed?)"
    exit 1;
elif
    pyver="$(python3 --version 2>&1)"
    pyver="${pyver#Python 3.}"
    pyver="${pyver%%.*}"
    [ $(expr "$pyver" '>=' 6) != 1 ]
then
    echo "Python version too old, (3.6 or newer required)" # Assumes CPython.
    exit 1;
fi

testfunc() {
    rm -f failed-*.dat success-*.dat
    n=0

    testdrv=../src/2-hash/b3-testvec.py
    $testdrv | {
        while read inlen ; do
            $testdrv $inlen | $exec xBLAKE3_ForTest > hash-res.dat #- &
            $testdrv $inlen hash > hash-ref.dat
            # add other scenario tests.?
            #- wait

            for i in ref res ; do eval "$i=\$(cat hash-$i.dat)" ; done # add ret ?
            if [ "$ref" != "$res" ] # || [ "$ref" != "$ret" ]
            then
                echo BLAKE3 len=${inlen} failed with "$ref" != "$res"
                n=$((n+1))
                $testdrv $inlen > failed-blake3-$inlen.$arch.dat
            fi
            rm hash-re[fst].dat
        done
        printf "%u failed tests.\n" $n
        if [ $n -gt 0 ]
        then return 1
        else return 0
        fi ; }
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
blake3-test.c
blake3.c
1-oslib/TCrew-Stub.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
