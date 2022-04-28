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
xecdh-self-fed-test.c
x25519.c
2-ec/ec-common.c
2-ec/ecMt.c
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

#cflags="-D SSLEN=32 -D TestCurve=secp256r1"
srcset="Curve25519"
tests_run

#cflags="-D SSLEN=48 -D TestCurve=secp384r1"
# srcset="Curve448"
# tests_run
