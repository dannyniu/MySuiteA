#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
cmac-aes-t-test.c
cmac-aes.c
cmac.c
0-datum/endian.c
"

. ../1-symm/rijndael-variants.sh.inc
