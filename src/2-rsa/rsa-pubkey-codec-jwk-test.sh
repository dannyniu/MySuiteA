#!/bin/sh

optimize=true
testfunc() {
    #lldb \
        $exec ../tests/rsa-1440-pub.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
rsa-pubkey-codec-jwk-test.c
rsa-pubkey-jwk-der-conv.c
2-asn1/der-codec.c
2-pkc-xfmt/pkc-xfmt.c
"

arch_family=defaults
srcset="Plain C"

tests_run
