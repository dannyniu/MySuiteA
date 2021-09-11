#!/bin/sh

testfunc() {
    $exec #"$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsaes-oaep-correctness-test.c
rsaes-oaep-dec.c
rsaes-oaep-enc.c
2-rsa/pkcs1-padding.c
2-rsa/rsa-enc.c
2-rsa/rsa-fastdec.c
2-rsa/rsa-keygen.c
2-rsa/rsa-pubkey-codec-der.c
2-rsa/rsa-privkey-writer-der.c
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

arch=x86_64 cflags="-D KEYGEN_LOGF"
( . $unitest_sh )

arch=aarch64 cflags="-D KEYGEN_LOGF"
( . $unitest_sh )

arch=powerpc64 cflags="-D KEYGEN_LOGF"
( . $unitest_sh )

arch=sparc64 cflags="-D KEYGEN_LOGF"
( . $unitest_sh )
