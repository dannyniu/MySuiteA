#!/bin/sh

cat <<EOF
Self-fed test for SLH-DSA (a.k.a. SPHINCS+) consume huge amount of
stack space, and it's not practical to perform this test. Exiting.
EOF

exit 0

optimize=debug
testfunc() {
    #lldb \
        $exec "$(date)"
}

cd "$(dirname "$0")"
unitest_sh=../unitest.sh
. $unitest_sh

src="\
slhdsa-self-fed-test.c
slhdsa.c
sphincs-subroutines-wots.c
sphincs-subroutines-xmss.c
sphincs-subroutines-fors.c
sphincs-subroutines-hypertree.c
sphincs-hash-params-family-sha256.c
sphincs-hash-params-family-sha512.c
sphincs-hash-params-family-sha2-common.c
sphincs-hash-params-family-shake.c
2-hash/sha.c
2-mac/hmac-sha.c
2-mac/hmac.c
2-xof/shake.c
2-xof/gimli-xof.c
1-symm/keccak-f-1600.c
1-symm/gimli.c
1-symm/fips-180.c
1-symm/sponge.c
0-datum/endian.c
"

arch_family=defaults

cflags="-D HashN=16 -D HashH=63 -D LongHash=SHA256 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-128s"
tests_run ; exit

cflags="-D HashN=16 -D HashH=66 -D LongHash=SHA256 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-128f"
tests_run

cflags="-D HashN=24 -D HashH=63 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-192s"
tests_run

cflags="-D HashN=24 -D HashH=66 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-192f"
tests_run

cflags="-D HashN=32 -D HashH=64 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-256s"
tests_run

cflags="-D HashN=32 -D HashH=68 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-256f"
tests_run

cflags="-D HashN=16 -D HashH=63 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-128s"
tests_run

cflags="-D HashN=16 -D HashH=66 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-128f"
tests_run

cflags="-D HashN=24 -D HashH=63 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-192s"
tests_run

cflags="-D HashN=24 -D HashH=66 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-192f"
tests_run

cflags="-D HashN=32 -D HashH=64 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-256s"
tests_run

cflags="-D HashN=32 -D HashH=68 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-256f"
tests_run
