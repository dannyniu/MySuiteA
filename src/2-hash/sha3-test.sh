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

        for b in 224 256 384 512; do
            ../src/2-hash/shasum.py sha3_$b < $testvec > hash-ref.dat &
            $exec xSHA3_$b < $testvec > hash-res.dat &
            $exec iSHA3_$b < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo sha3-${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-sha3-${b}-$mlen.$datetime.$arch.dat
            fi
            rm hash-re[fst].dat
        done

        for b in 128 256; do
            ../src/2-hash/shakesum.py shake_$b < $testvec > hash-ref.dat &
            $exec xSHA3_${b}000 < $testvec > hash-res.dat &
            $exec iSHA3_${b}000 < $testvec > hash-ret.dat &
            wait

            for i in ref res ret ; do eval "$i=\$(cat hash-$i.dat)" ; done
            if [ "$ref" != "$res" ] || [ "$ref" != "$ret" ] ; then
                echo shake${b} failed with $ref:$res:$ret
                n=$((n+1))
                cp $testvec failed-shake-${b}-$mlen.$datetime.$arch.dat
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
sha3-test.c
sha3.c
2-xof/shake.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
src="1-symm/keccak-f-1600.c"
srcset="Plain C"

tests_run
