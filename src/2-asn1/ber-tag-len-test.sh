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
. $unitest_sh

src="\
ber-tag-len-test.c
der-codec.c
"

arch_family=defaults
srcset="Plain C"

tests_run
