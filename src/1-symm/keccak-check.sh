#!/bin/sh

optimize=debug
testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
keccak-check.c
0-datum/endian.c
"

. ./keccak-variants.sh.inc
