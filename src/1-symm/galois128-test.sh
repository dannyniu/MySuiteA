#!/bin/sh

testfunc() {
    for n in $testnum
    do $exec < testblob-$n.dat > output-$n-$srctype-$arch.dat
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="galois128-test.c 0-datum/endian.c"
bin=$(basename "$0" .sh)

vsrc(){ src="$src_common galois128${1}.c" ; }

testnum="01 02 03 04 05 06"
for n in $testnum
do dd if=/dev/urandom bs=16 count=3 of=../../bin/testblob-$n.dat
done 2>/dev/null

srctype=c

arch=x86_64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=aarch64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=powerpc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=sparc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

srctype=x

arch=x86_64 cflags="-mpclmul" srcset="x86 PCLMUL"
vsrc "-x86"
( . $unitest_sh )

arch=aarch64 cflags="-march=armv8-a+crypto" srcset="ARM NEON Crypto"
vsrc "-arm"
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
