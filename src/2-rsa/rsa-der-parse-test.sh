#!/bin/sh

testfunc() {
    $exec ../tests/rsa-1440-3primes.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsa-der-parse-test.c
rsa-privkey-parser-der.c
2-asn1/der-codec.c
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
