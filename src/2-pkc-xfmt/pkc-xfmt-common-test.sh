#!/bin/sh

optimize=debug
testfunc() {
    $exec 0 - || return
    [ $($exec 1 '["a", "b", "c", null]' 3 #|
            : tee /dev/tty) = null ] || return
    [ $($exec 2 '{ "x": 3, "y": 4, "p": 2.0, "h": 5 }' p #|
            : tee /dev/tty) = 2.0 ] || return
    ! $exec 3 '{ "x": 1, "y": 2, "x": 3 }' || return
    ! $exec 3 '{ "x": 1, $4: 2, "y": 3 }' || return
    $exec 3 '{ "x": 1, "4": 2, "y": 3 }' || return
    $exec 4 || return
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
pkc-xfmt-common-test.c
pkc-xfmt.c
2-asn1/der-codec.c
"

arch_family=defaults
srcset="Plain C"

tests_run
