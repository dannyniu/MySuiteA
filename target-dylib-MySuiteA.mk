# DannyNiu/NJF, 2025-12-25. Public Domain.

## basic information. ##

LibraryName = MySuiteA
ProductName = lib${LibraryName}
MajorVer = 0
MinorVer = 4
ProductVer = ${MajorVer}.${MinorVer}
ProductRev = ${ProductVer}.0

PkgConfigName = MySuiteA Dynamic Library
PkgConfigDesc = The MySuiteA Cryptography Library.
PkgConfigURLs = \
	https://github.com/dannyniu/MySuiteA \
	https://gitee.com/dannyniu/MySuiteA

## target product. ##

FILE_EXT_ELF = so.${ProductVer}
FILE_EXT_MACHO = ${ProductVer}.dylib

FILE_EXT = ${FILE_EXT_MACHO}

ccOpts = -Wall -Wextra -fPIC # If I guessed wrong, specify on command line.
LD = ${CC} # 2024-03-09: direct linker invocation lacks some default flags.

# ``-G'' is the System V and XPG-8/SUSv5 option for producing
# dynamic-linking library. Will need adaptation for pre-existing linkers.
DLLFLAGS = -shared

## object files. ##

include objects.mk

OBJS_GROUP_WITH_ADDITION =
CFLAGS_GROUP_WITH =

INPUT_OBJECTS = ${OBJS_GROUP_ALL} ${OBJS_GROUP_WITH_ADDITION}
CFLAGS = ${ccOpts} ${CFLAGS_GROUP_WITH}
