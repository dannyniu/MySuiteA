#!/bin/sh

testfunc() {
    $exec ../tests/rsa-1440-3primes.der ../tests/rsa-1440-pub.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
rsa-pubkey-codec-der-test.c
rsa-pubkey-export-der.c
rsa-pubkey-parser-der.c
rsa-pubkey-writer-der.c
rsa-privkey-parser-der.c
2-asn1/der-codec.c
1-integers/vlong-dat.c
"

bin=$(basename "$0" .sh)
srcset="Plain C"
optimize=true

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
