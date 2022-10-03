#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ccm-check.c
ccm-aes.c
ccm.c
0-datum/endian.c
"

. ../1-symm/rijndael-variants.sh.inc
