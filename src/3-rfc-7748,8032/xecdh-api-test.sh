#!/bin/sh

optimize=true
testfunc() {
    # lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
xecdh-api-test.c
rfc-7748.c
2-ec/ec-common.c

2-ec/ecMt.c
2-ec/curve25519.c
2-ec/curve448.c
2-ec/modp25519.c
2-ec/modp448.c
1-integers/vlong.c
1-integers/vlong-dat.c
2-xof/gimli-xof.c
1-symm/gimli.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

keygen_log="" # "-D KEYGEN_LOGF_STDIO"
cflags_common="$keygen_log"

cflags="-D TestCurve=X25519"
srcset="Curve25519"
tests_run

cflags="-D TestCurve=X448"
srcset="Curve448"
tests_run
