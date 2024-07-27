# DannyNiu/NJF, 2024-07-27. Public Domain.

LibraryName = MySuiteA
ProductName = lib${LibraryName}
MajorVer = 0
MinorVer = 2
ProductVer = ${MajorVer}.${MinorVer}
ProductRev = ${ProductVer}.1

FILE_EXT_ELF = so.${ProductVer}
FILE_EXT_MACHO = ${ProductVer}.dylib

FILE_EXT = ${FILE_EXT_MACHO}

CFLAGS = -Wall -Wextra -fPIC # If I guessed wrong, specify on command line.
LD = ${CC} # 2024-03-09: direct linker invocation lacks some default flags.

# ``-G'' is the System V and XPG-8/SUSv5 option for producing
# dynamic-linking library. Will need adaptation for pre-existing linkers.
DLLFLAGS = -G

OBJS_GROUP_WITH_ADDITIONAL =
CFLAGS_GROUP_WITH =

INPUT_OBJECTS = ${OBJS_GROUP_ALL} ${OBJS_GROUP_WITH_ADDITIONAL}

prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir  = ${prefix}/include

# 2022-12-30:
# Each product consist of:
# - Name - obviously,
# - Versioning - semver, *.so.{ver} on ELF, *.{ver}.dylib on Mach-O
# MySuiteA is best used from source code directly; not everyone use
# every algorithm implemented in the suite
