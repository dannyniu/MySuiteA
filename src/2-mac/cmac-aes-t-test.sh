#!/bin/sh

testfunc() {
    $exec
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
src_common="
cmac-aes-t-test.c
cmac-aes.c
cmac.c
0-datum/endian.c
"
bin=$(basename "$0" .sh)

vsrc(){ src="$src_common 1-symm/rijndael${1}.c" ; }

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

arch=x86_64 cflags="-maes" srcset="x86 AESNI"
vsrc "-x86"
( . $unitest_sh )

arch=aarch64 cflags="-march=armv8-a+crypto" srcset="ARM NEON Crypto"
vsrc "-arm"
( . $unitest_sh )
