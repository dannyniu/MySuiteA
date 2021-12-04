#!/bin/sh

testfunc() {
    #lldb \
        $exec ../tests/rsa-1440-3primes.der
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsa-fastdec-test.c
rsa-fastdec.c
rsa-privkey-parser-der.c
rsa-privkey-writer-der.c
2-asn1/der-codec.c
1-integers/vlong.c
1-integers/vlong-dat.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"
optimize=true

arch=x86_64 cflags=""
( . $unitest_sh )

arch=aarch64 cflags=""
( . $unitest_sh )

arch=powerpc64 cflags=""
( . $unitest_sh )

arch=sparc64 cflags=""
( . $unitest_sh )
