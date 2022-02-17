#!/bin/sh

testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
rsa-keygen-test.c
rsa-keygen.c
rsa-privkey-parser-der.c
rsa-privkey-writer-der.c
1-integers/vlong.c
1-integers/vlong-dat.c
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
cflags_common="-D KEYGEN_LOGF_STDIO"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
