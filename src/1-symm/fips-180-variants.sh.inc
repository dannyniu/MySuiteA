# DannyNiu/NJF, 2022-10-03. Public Domain.

arch_family=defaults
src="1-symm/fips-180.c"
srcset="Plain C"

tests_run

arch_family=x86 # AMD CPUs Only for now.
cflags="-msha -mssse3 -D TEST_WITH_MOCK -D NI_FIPS180=NI_ALWAYS"
src="1-symm/fips-180-x86.c"
srcset="x86 SHA Extensions"

tests_run

arch_family=arm # Apple Silicons Only for now.
cflags="-march=armv8-a+crypto+sha3 -D NI_FIPS180=NI_ALWAYS"
src="1-symm/fips-180-arm.c"
srcset="ARMv8.4-A Crypto Extensions"

if [ "$(uname -sm)" = "Darwin arm64" ] ; then tests_run ; fi
