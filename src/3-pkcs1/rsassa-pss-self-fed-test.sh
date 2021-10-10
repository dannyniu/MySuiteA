#!/bin/sh

testfunc() {
    #lldb \
        $exec #"$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsassa-pss-self-fed-test.c
rsassa-pss-sign.c
rsassa-pss-verify.c
pkcs1.c
2-rsa/pkcs1-padding.c
2-rsa/rsa-enc.c
2-rsa/rsa-fastdec.c
2-rsa/rsa-keygen.c
2-rsa/rsa-privkey-parser-der.c
2-rsa/rsa-privkey-writer-der.c
2-rsa/rsa-pubkey-codec-der.c
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
bin=$(basename "$0" .sh)
srcset="Plain C"
optimize=true

keygen_log="" # "-D KEYGEN_LOGF_STDIO"

arch=x86_64 cflags="$keygen_log"
( . $unitest_sh )

arch=aarch64 cflags="$keygen_log"
( . $unitest_sh )

arch=powerpc64 cflags="$keygen_log"
( . $unitest_sh )

arch=sparc64 cflags="$keygen_log"
( . $unitest_sh )
