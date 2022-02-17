#!/bin/sh

testfunc() {
    e=0
    for b in 128 192 256 ; do
        for f in ../tests/KAT_AES/ECB*${b}.rsp ; do
            $exec $b < $f || e=$((e+1))
        done
    done
    echo "$e set(s) of test vectors failed."
    if [ $e -gt 0 ]
    then return 1
    else return 0
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src_common="aes-test.c 0-datum/endian.c"
bin=$(basename "$0" .sh)

cflags=""
srcset="Plain C"
src="rijndael.c"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

arch=x86_64
cflags="-maes"
srcset="AESNI"
src="rijndael-x86.c"
( . $unitest_sh ) || ret=1

arch=aarch64
cflags="-march=armv8-a+crypto"
srcset="ARM NEON Crypto"
src="rijndael-arm.c"
( . $unitest_sh ) || ret=1

exit $ret
