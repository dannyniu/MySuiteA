# DannyNiu/NJF, 2022-10-03. Public Domain.

arch_family=defaults
cflags=""
src="1-symm/keccak-f-1600.c"
srcset="Plain C"

tests_run

arch_family=arm # Apple Silicons Only for now.
cflags="-march=armv8-a+crypto+sha3 -D NI_KECCAK=NI_ALWAYS"
src="1-symm/keccak-f-1600-arm.c"
srcset="ARMv8.4-A Crypto Extensions"

if [ "$(uname -sm)" = "Darwin arm64" ] ; then tests_run ; fi
