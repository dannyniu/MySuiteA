#!/bin/sh

cd "$(dirname "$0")"

obj=""
sep=''

for c in sha.c sha3.c ; do
    obj="$obj${sep}../2-hash/${c}"
    sep=' '
done

for c in shake.c ; do
    obj="$obj${sep}../2-xof/${c}"
    sep=' '
done

for c in fips-180 keccak-f-1600 sponge ; do
    obj="$obj${sep}../1-symm/${c}.c"
    sep=' '
done

for c in curve-secp256r1 curve-secp384r1 ; do
    obj="$obj${sep}../2-ec/${c}.c"
    sep=' '
done

misc="../0-datum/endian.c ../0-exec/ldstub.c"

for t in *-paramset.c ; do
    src=""
    sep=''

    for c in ${t%-paramset.c}*.c ; do
        case "$c" in
            *-test.c|*-paramset.c)
                : ;;
            *)
                src="$src$sep$c"
                sep=' '
                ;;
        esac
    done

    for c in der-codec.c ; do
        src="$src${sep}../2-asn1/${c}"
        sep=' '
    done

    for c in 3-ecc-common/ecc-common.c ; do
        src="$src${sep}../${c}"
        sep=' '
    done

    for c in ec-common ecp-xyz ecp-pubkey-codec ; do
        src="$src${sep}../2-ec/${c}.c"
        sep=' '
    done

    for c in vlong.c vlong-dat.c ; do
        src="$src${sep}../1-integers/${c}"
        sep=' '
    done

    echo ==== "$t" ====
    if cc -o /tmp/deleteme $t $obj $src $misc &&
            cc -o /tmp/deleteme $src $misc
    then printf '\033[42;33m%s\033[0m\n' passing ; true
    else printf '\033[41;34m%s\033[0m\n' failing ; false
    fi
done
