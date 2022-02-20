#!/bin/sh

optimize=true
testfunc() {
    $exec ../tests/rsa-1440-3primes.der ../tests/rsa-1440-pub.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
rsa-pubkey-codec-der-test.c
rsa-pubkey-export-der.c
rsa-pubkey-parser-der.c
rsa-pubkey-writer-der.c
rsa-privkey-parser-der.c
2-asn1/der-codec.c
1-integers/vlong-dat.c
"

arch_family=defaults
srcset="Plain C"

tests_run
