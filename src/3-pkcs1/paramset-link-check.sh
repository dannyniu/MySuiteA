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

misc="../0-datum/endian.c ../0-exec/ldstub.c"

for t in *-paramset.c ; do
    src=""
    sep=''

    for c in pkcs1.c ${t%-paramset.c}*.c ; do
        case "$c" in
            *-test.c|*-paramset.c)
                : ;;
            *)
                src="$src$sep$c"
                sep=' '
                ;;
        esac
    done

    for c in ../2-rsa/pkcs1-padding.c ../2-rsa/rsa-p*key-*-der.c ; do
        src="$src$sep$c"
        sep=' '
    done

    for c in der-codec.c ; do
        src="$src${sep}../2-asn1/${c}"
        sep=' '
    done

    for c in enc fastdec keygen ; do
        src="$src${sep}../2-rsa/rsa-${c}.c"
        sep=' '
    done

    for c in vlong.c vlong-dat.c ; do
        src="$src${sep}../1-integers/${c}"
        sep=' '
    done

    for c in EGCD.c MillerRabin.c ; do
        src="$src${sep}../2-numbertheory/${c}"
        sep=' '
    done

    echo ==== "$t" ====
    if cc -o /tmp/deleteme pkcs1-paramset-common.c $t $obj $src $misc &&
            case "$t" in
                rsassa-pkcs1-v1_5-paramset.c)
                    cc -o /tmp/deleteme $src $misc $obj
                    ;;
                *)
                    cc -o /tmp/deleteme $src $misc
                    ;;
            esac
    then printf '\033[42;33m%s\033[0m\n' passing ; true
    else printf '\033[41;34m%s\033[0m\n' failing ; false
    fi
done
