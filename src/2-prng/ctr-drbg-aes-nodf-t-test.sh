#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
ctr-drbg-aes-nodf-t-test.c
ctr-drbg.c
0-datum/endian.c
"
cflags_common="-D CTR_DRBG_OMIT_DF"

. ../1-symm/rijndael-variants.sh.inc
