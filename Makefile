# DannyNiu/NJF, 2023-03-18. Public Domain.

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
LD=${CC}

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

include inc-config.mk
include objects.mk

# 2022-12-30:
# Each product consist of:
# - Name - obviously,
# - Versioning - semver, *.so.{ver} on ELF, *.{ver}.dylib on Mach-O
# MySuiteA is best used from source code directly; not everyone use
# every algorithm implemented in the suite

.PHONY: all clean distclean

all: build/${ProductName}.${FILE_EXT} build/include build/${ProductName}.pc

install:
	mkdir -p ${libdir}/pkgconfig ${includedir}
	cp build/"${ProductName}".pc ${libdir}/pkgconfig
	cp build/"${ProductName}.${FILE_EXT}" ${libdir}
	if [ -e ${includedir}/MySuiteA ] ; then \
		echo include headers director exists! ; \
		false ; \
	else cp -R -L build/include ${includedir}/MySuiteA ; fi

uninstall:
	rm ${libdir}/pkgconfig/"${ProductName}".pc
	rm ${libdir}/"${ProductName}.${FILE_EXT}"
	rm -R ${includedir}/MySuiteA

clean:
	rm -f build/"${ProductName}.${FILE_EXT}"
	rm -f build/"${ProductName}.pc"
	rm -Rf build/include
	rm -f ${OBJS_GROUP_ALL} ${OBJS_GROUP_WITH_ADDITIONAL}

distclean: clean
	rm -f inc-config.mk auto/configure[-.]*

build/${ProductName}.${FILE_EXT}: ${INPUT_OBJECTS}
	${LD} ${DLLFLAGS} ${LDFLAGS} ${INPUT_OBJECTS} -o $@

build/include:
	mkdir -p build/include
	cd src ; find . -name \*.h ! -name \*.c.h ! -name \*largeint\* | \
		while read e ; do \
                mkdir -p "../build/include/$$(dirname "$$e")" ; \
                ln -s "$$PWD/$$e" "../build/include/$$e" ; \
                done

build/${ProductName}.pc:
	printf '%s\n' \
		"prefix=${prefix}" "exec_prefix=${exec_prefix}" \
		"libdir=${libdir}" "includedir=${includedir}" \
		"Name: MySuiteA Dynamic Library" \
		"Version: ${ProductRev}" \
		"Description: The MySuiteA Cryptography Library." \
		"URL: https://github.com/dannyniu/MySuiteA" \
		"URL: https://gitee.com/dannyniu/MySuiteA" \
		'Cflags: -I$${includedir} '"${CFLAGS_GROUP_WITH}" \
		'Libs: -L$${libdir} -lMySuiteA' \
		> build/libMySuiteA.pc
