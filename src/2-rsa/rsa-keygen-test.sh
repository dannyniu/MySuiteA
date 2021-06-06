#!/bin/sh

testfunc() {
    $exec #"$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsa-keygen-test.c
rsa-keygen.c
rsa-privkey-parser-der.c
rsa-privkey-writer-der.c
1-integers/vlong.c
2-numbertheory/MillerRabin.c
2-numbertheory/EGCD.c
2-asn1/der-codec.c
2-xof/gimli-xof.c
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
