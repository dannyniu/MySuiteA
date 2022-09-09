#!/bin/sh

optimize=debug
testfunc() {
    #lldb \
        $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
KangarooTwelve-test.c
KangarooTwelve.c
1-symm/sponge.c
1-symm/keccak-f-1600.c
1-oslib/TCrew-Stub.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

tests_run
