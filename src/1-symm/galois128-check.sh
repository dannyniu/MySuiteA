#!/bin/sh

testfunc() {
    for n in $testnum
    do $exec < testblob-$n.dat > output-$n-$srctype-$arch.dat
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="galois128-check.c 0-datum/endian.c"

testnum="01 02 03 04 05 06"
for n in $testnum
do dd if=/dev/urandom bs=16 count=3 \
      of=${path_tmpid:-../../}/bin/testblob-$n.dat
done 2>/dev/null

srctype=c

arch_family=defaults
cflags=""
srcset="Plain C"
src="galois128.c"

tests_run

srctype=x

arch_family=x86
cflags="-mpclmul -DNI_GALOIS128=NI_ALWAYS"
srcset="x86 PCLMUL"
src="galois128-x86.c"

tests_run

arch_family=arm
cflags="-march=armv8-a+crypto -DNI_GALOIS128=NI_ALWAYS"
srcset="ARM NEON Crypto"
src="galois128-arm.c"

tests_run

arch_family=ppc
cflags="-mcpu=power8 -DNI_GALOIS128=NI_ALWAYS"
srcset="PowerPC AltiVec Crypto"
src="galois128-ppc.c"

tests_run

cd ../../bin
cmpfunc() {
    while [ $# -ge 2 ]
    do cmp $1 $2 ; echo Exited $? ; shift
    done
}
for n in $testnum ; do
    cmpfunc output-$n-[a-z]-*.dat
    #rm output-$n-[a-z]-*.dat testblob-$n.dat
done
