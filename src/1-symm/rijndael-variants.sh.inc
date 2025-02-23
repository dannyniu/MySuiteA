# DannyNiu/NJF, 2022-10-03. Public Domain.

arch_family=defaults
cflags=""
srcset="Plain C"
src="1-symm/rijndael.c"

tests_run

arch_family=x86
cflags="\
-maes \
-D GENSRC_WILLBE_INCLUDED \
-D NI_AES=NI_ALWAYS"
srcset="x86 AESNI"
src="1-symm/rijndael-x86.c"

tests_run

arch_family=arm
cflags="\
-march=armv8-a+crypto \
-D GENSRC_WILLBE_INCLUDED \
-D NI_AES=NI_ALWAYS"
srcset="ARM NEON Crypto"
src="1-symm/rijndael-arm.c"

tests_run

arch_family=ppc
cflags="\
-mcpu=power8 \
-D GENSRC_WILLBE_INCLUDED \
-D NI_AES=NI_ALWAYS"
srcset="PowerPC AltiVec Crypto"
src="1-symm/rijndael-ppc.c"

tests_run
