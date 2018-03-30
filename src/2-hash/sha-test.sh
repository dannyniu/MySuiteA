#!/bin/sh

testfunc() {
    rm -f failed-*.dat success-*.dat
    n=0
    testvec=testblob.dat
    mlen=0;
    while [ $mlen -lt 1000000 ] ; do
        dd if=/dev/urandom bs=32 count=$((mlen/32)) of=$testvec 2>/dev/null
        
        for b in 1 224 256 384 512 ; do
            ref="$(shasum -b -a $b < $testvec)"
            res="$($exec $b < $testvec)"
            if ! [ "${ref%%[!a-zA-Z0-9]*}" = $res ] ; then
                echo sha${b} failed with "$ref" != $res
                n=$((n+1))
                link $testvec failed-sha${b}-$mlen.$arch.dat
            else link $testvec success-sha${b}-$mlen.$arch.dat
            fi
        done
        
        for b in 224 256 384 512 128000 256000 ; do
            ref="$(sha3sum -b -a $b < $testvec)"
            res="$($exec 3$b < $testvec)"
            if ! [ "${ref%%[!a-zA-Z0-9]*}" = $res ] ; then
                echo sha3-${b} failed with "$ref" != $res
                n=$((n+1))
                link $testvec failed-sha3-${b}-$mlen.$arch.dat
            else link $testvec success-sha3-${b}-$mlen.$arch.dat
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
2-hash/sha-test.c
2-hash/sha.c
2-hash/sha3.c
2-xof/shake.c
1-symm/fips-180.c
1-symm/sponge.c
1-symm/keccak-f-1600.c
0-datum/endian.c
"
bin=sha-test

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
( . $unitest_sh )
