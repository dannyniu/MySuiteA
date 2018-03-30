#!/bin/sh

testfunc() {
    for n in $testnum
    do $exec < testblob-$n.dat > output-$n-$srctype-$arch.dat
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="galois128-test.c 0-datum/endian.c"
bin=galois128-test

testnum="01 02 03 04 05 06"
for n in $testnum
do dd if=/dev/urandom bs=16 count=3 of=../../bin/testblob-$n.dat
done

srctype=c

echo ================================================================
echo C language code. [x86_64]
arch=x86_64 cflags=""
src="$src_common galois128.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [aarch64]
arch=aarch64 cflags=""
src="$src_common galois128.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [powerpc64]
arch=powerpc64 cflags=""
src="$src_common galois128.c"
( . $unitest_sh )

echo ================================================================
echo C language code. [sparc64]
arch=sparc64 cflags=""
src="$src_common galois128.c"
( . $unitest_sh )

srctype=x

echo ================================================================
echo x86 PCLMUL intrinsics.
arch=x86_64 cflags="-mpclmul"
src="$src_common galois128-x86.c"
( . $unitest_sh )

echo ================================================================
echo ARM NEON Crypto intrinsics.
arch=aarch64 cflags="-march=armv8-a+crypto"
src="$src_common galois128-arm.c"
( . $unitest_sh )

cd ../../bin
cmpfunc() {
    while [ $# -ge 2 ]
    do cmp $1 $2 ; echo Exited $? ; shift
    done
}
for n in $testnum ; do
    cmpfunc output-$n-[a-z]-*.dat
    rm output-$n-[a-z]-*.dat testblob-$n.dat
done
