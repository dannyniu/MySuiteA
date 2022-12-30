#!/bin/sh

testfunc() {
    exec1="$exec"
    if [ "$srcset" = "ARMv8.4-A Crypto Extensions" ] && [ $arch = $sysarch ]
    then exec1="qemu-aarch64 $exec" ; fi

    $exec1
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src_common="\
sm2sig-sign-test.c
sm2sig.c
3-ecc-common/ecc-common.c
2-ec/ec-common.c
2-ec/ecp-xyz.c
2-ec/ecp-pubkey-codec.c
2-ec/curveSM2.c
2-hash/sm3.c
2-asn1/der-codec.c
1-integers/vlong.c
1-integers/vlong-dat.c
0-datum/endian.c
"

arch_family=defaults
cflags=""
src="1-symm-national/gbt-32905.c"
srcset="Plain C"

tests_run

# 2022-10-04:
# SM3 has too few test cases. Borrowing SM2-ECDSA for coverage.

arch_family=arm
cflags="-march=armv8.2-a+crypto+sm4 -D NI_SM3=NI_ALWAYS"
src="1-symm-national/gbt-32905-arm.c"
srcset="ARMv8.4-A Crypto Extensions"

tests_run
