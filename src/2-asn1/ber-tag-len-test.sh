#!/bin/sh

testfunc() {
    if $exec
    then echo test passed
    else echo test failed
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
ber-tag-len-test.c
der-codec.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
