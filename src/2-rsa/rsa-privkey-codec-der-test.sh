#!/bin/sh

optimize=debug
testfunc() {
    #lldb --\
        $exec ../tests/rsa-1440-3primes.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
rsa-privkey-codec-der-test.c
rsa-privkey-parser-der.c
rsa-privkey-writer-der.c
2-asn1/der-codec.c
1-integers/vlong-dat.c
"

arch_family=defaults
srcset="Plain C"

tests_run
