#!/bin/sh

optimize=debug
testfunc() {
    #lldb \
        $exec | openssl asn1parse -inform DER
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
rsa-privkey-der-from-jwk-oth-check.c
2-pkc-xfmt/pkc-xfmt.c
2-asn1/der-codec.c
"

arch_family=defaults
srcset="Plain C"

tests_run
