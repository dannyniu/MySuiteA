#!/bin/sh

optimize=debug
testfunc() {
    export exec1="$exec"
    if [ "$(uname -sm)" != "Darwin arm64" ] &&
           [ "$srcset" = "ARMv8.4-A Crypto Extensions" ]
    then export exec1="qemu-aarch64 $exec" ; fi

    $exec1
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
keccak-check.c
0-datum/endian.c
"

. ./keccak-variants.sh.inc
