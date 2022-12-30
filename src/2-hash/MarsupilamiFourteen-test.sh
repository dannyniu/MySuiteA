#!/bin/sh

testfunc() {
    export exec1="$exec"
    if [ "$(uname -sm)" != "Darwin arm64" ] &&
           [ "$srcset" = "ARMv8.4-A Crypto Extensions" ] &&
           [ $arch = $sysarch ]
    then export exec1="qemu-aarch64 $exec" ; fi
    ../src/2-hash/MarsupilamiFourteen-test.py
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
MarsupilamiFourteen-test.c
KangarooTwelve.c
1-symm/sponge.c
1-oslib/TCrew.c
1-oslib/TCrew-Stub.c
0-datum/endian.c
"

. ../1-symm/keccak-variants.sh.inc
