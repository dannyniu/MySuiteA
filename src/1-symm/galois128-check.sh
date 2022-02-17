#!/bin/sh

testfunc() {
    for n in $testnum
    do $exec < testblob-$n.dat > output-$n-$srctype-$arch.dat
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src_common="galois128-check.c 0-datum/endian.c"
bin=$(basename "$0" .sh)

testnum="01 02 03 04 05 06"
for n in $testnum
do dd if=/dev/urandom bs=16 count=3 of=../../bin/testblob-$n.dat
done 2>/dev/null

srctype=c

cflags=""
srcset="Plain C"
src="galois128.c"

arch=x86_64
( . $unitest_sh )

arch=aarch64
( . $unitest_sh )

arch=powerpc64
( . $unitest_sh )

arch=sparc64
( . $unitest_sh )

srctype=x

arch=x86_64
cflags="-mpclmul"
srcset="x86 PCLMUL"
src="galois128-x86.c"
( . $unitest_sh )

arch=aarch64
cflags="-march=armv8-a+crypto"
srcset="ARM NEON Crypto"
src="galois128-arm.c"
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
