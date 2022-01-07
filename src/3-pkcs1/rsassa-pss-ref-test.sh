#!/bin/sh

testfunc() {
    n=0
    fail=0
    total=$((80 / 5))
    while [ $n -lt $total ] ; do
        s="$(date):$RANDOM"
        ../src/3-pkcs1/rsassa-pss-ref-test.py "$s" |
            $exec "$s" || fail=$((fail + 1))
        n=$((n + 1))
    done

    echo $fail of $total tests failed
    if [ $fail -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src="
rsassa-pss-ref-test.c
rsassa-pss-verify.c
pkcs1.c
2-rsa/pkcs1-padding.c
2-rsa/rsa-enc.c
2-rsa/rsa-pubkey-parser-der.c
2-rsa/rsa-pubkey-writer-der.c
2-hash/sha.c
1-integers/vlong.c
1-integers/vlong-dat.c
2-numbertheory/MillerRabin.c
2-numbertheory/EGCD.c
2-asn1/der-codec.c
1-symm/fips-180.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)
srcset="Plain C"
variant="-D PKC_OMIT_PRIV_OPS"
optimize=true

keygen_log="" # "-D KEYGEN_LOGF_STDIO"

arch=x86_64 cflags="$variant $keygen_log"
( . $unitest_sh )

arch=aarch64 cflags="$variant $keygen_log"
( . $unitest_sh )

arch=powerpc64 cflags="$variant $keygen_log"
( . $unitest_sh )

arch=sparc64 cflags="$variant $keygen_log"
( . $unitest_sh )
