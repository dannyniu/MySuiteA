# DannyNiu/NJF, 2022-10-03. Public Domain.

# 2022-10-03:
# Because HMAC tests are testing SHA-1,2,3 together, this variants file list
# all source file and compiling flags for all these hashing algorithms.
# This file solves exactly this 1 problem and is used exactly once (u1s1).
#
# SHA-3 had been optimized using compiler intrinsics as of 2022-10-04.

arch_family=defaults
cflags=""
src="1-symm/fips-180.c 1-symm/keccak-f-1600.c"
srcset="Plain C"

tests_run

arch_family=x86 # AMD CPUs Only for now.
cflags="\
-msha -mssse3 \
-D GENSRC_WILLBE_INCLUDED \
-D TEST_WITH_MOCK \
-D NI_FIPS180=NI_ALWAYS"
src="1-symm/fips-180-x86.c 1-symm/keccak-f-1600.c"
srcset="x86 SHA Extensions"

tests_run

arch_family=arm # Apple Silicons Only for now.
cflags="\
-march=armv8.2-a+crypto+sha3 \
-D GENSRC_WILLBE_INCLUDED \
-D NI_FIPS180=NI_ALWAYS \
-D NI_KECCAK=NI_ALWAYS"
src="1-symm/fips-180-arm.c 1-symm/keccak-f-1600-arm.c"
srcset="ARMv8.4-A Crypto Extensions"

if [ "$(uname -sm)" = "Darwin arm64" ] ; then tests_run ; fi
