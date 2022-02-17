#!/bin/sh

testfunc() {
    $exec
    if [ $? = 0 ]
    then echo test passed ; true
    else echo test failed ; false
    fi
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh

ret=0
src="
ber-tag-len-test.c
der-codec.c
"

bin=$(basename "$0" .sh)
srcset="Plain C"

arch=x86_64
( . $unitest_sh ) || ret=1

arch=aarch64
( . $unitest_sh ) || ret=1

arch=powerpc64
( . $unitest_sh ) || ret=1

arch=sparc64
( . $unitest_sh ) || ret=1

exit $ret
