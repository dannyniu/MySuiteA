#!/bin/sh

optimize=true
testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
rsassa-pkcs1-v1_5-api-test.c
rsassa-pkcs1-v1_5.c
rsassa-pkcs1-v1_5-sign.c
rsassa-pkcs1-v1_5-verify.c
pkcs1.c
2-rsa/pkcs1-padding.c
2-rsa/rsa-enc.c
2-rsa/rsa-fastdec.c
2-rsa/rsa-keygen.c
2-rsa/rsa-privkey-parser-der.c
2-rsa/rsa-privkey-writer-der.c
2-rsa/rsa-pubkey-export-der.c
2-rsa/rsa-pubkey-parser-der.c
2-rsa/rsa-pubkey-writer-der.c
2-hash/sha.c
1-integers/vlong.c
1-integers/vlong-dat.c
2-numbertheory/MillerRabin.c
2-numbertheory/EGCD.c
2-asn1/der-codec.c
2-xof/gimli-xof.c
1-symm/fips-180.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults
srcset="Plain C"

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

tests_run
