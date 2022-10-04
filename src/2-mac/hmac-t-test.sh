#!/bin/sh

if ! command -v python3 >/dev/null ; then
    echo "Cannot invoke python3. (Not installed?)"
    exit 1
elif
    pyver="$(python3 --version 2>&1)"
    pyver="${pyver#Python 3.}"
    pyver="${pyver%%.*}"
    [ $(expr "$pyver" '>=' 6) != 1 ]
then
    echo "Python version too old, (3.6 or newer required)" # Assumes CPython.
    exit 1;
fi

hash_algos="
sha1
sha224
sha256
sha384
sha512
sha3_224
sha3_256
sha3_384
sha3_512
"

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

. ./hmac-testfunc.sh.inc

src_common="\
hmac-t-test.c
hmac-sha.c
hmac-sha3.c
hmac.c
2-hash/sha.c
2-hash/sha3.c
1-symm/sponge.c
0-datum/endian.c
"

. ../1-symm/fips-hash-variants.sh.inc
