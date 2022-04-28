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
sm2sig-api-test.c
sm2sig.c
3-ecc-common/ecc-common.c
2-ec/ec-common.c
2-ec/ecp-xyz.c
2-ec/ecp-pubkey-codec.c
2-ec/curveSM2.c
2-ec/curve-secp256r1.c
2-hash/sm3.c
2-asn1/der-codec.c
1-integers/vlong.c
1-integers/vlong-dat.c
2-xof/gimli-xof.c
1-symm-national/gbt-32905.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

srcset="curveSM2+SM3"
tests_run
