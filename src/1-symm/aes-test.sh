#!/bin/sh

testfunc() {
    for b in 128 192 256 ; do
        for f in ../tests/KAT_AES/ECB*${b}.rsp ; do
            $exec $b < $f
            echo "${bin##*/} $b < ${f##*/}: Exited: $?"
        done
    done
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="aes-test.c 0-datum/endian.c"
bin=$(basename "$0" .sh)

vsrc(){ src="$src_common rijndael${1}.c" ; }

arch=x86_64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=aarch64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=powerpc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=sparc64 cflags="" srcset="Plain C"
vsrc ""
( . $unitest_sh )

arch=x86_64 cflags="-maes" srcset="AESNI"
vsrc "-x86"
( . $unitest_sh )

arch=aarch64 cflags="-march=armv8-a+crypto" srcset="ARM NEON Crypto"
vsrc "-arm"
( . $unitest_sh )
