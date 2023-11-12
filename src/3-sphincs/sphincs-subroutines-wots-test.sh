#!/bin/sh

optimize=debug
testfunc() {
    #lldb \
        $exec < /dev/urandom
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
sphincs-subroutines-wots-test.c
sphincs-subroutines-wots.c
sphincs-hash-params-family-sha2-common.c
sphincs-hash-params-family-sha256.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-hash/sha.c
1-symm/fips-180.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"
tests_run
