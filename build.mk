# DannyNiu/NJF, 2024-07-27. Public Domain.

include common.mk
include objects.mk

include inc-config.mk

.PHONY: all

all: build/${ProductName}.${FILE_EXT} build/include build/${ProductName}.pc

build/${ProductName}.${FILE_EXT}: ${INPUT_OBJECTS}
	${LD} ${DLLFLAGS} ${LDFLAGS} ${INPUT_OBJECTS} -o $@

headers_select_expr='case "$$1" in *.h) echo "$$1";; *.c.h) [ "$$1" != $${1%.c.h} ] && '
build/include:
	mkdir -p build/include
	cd src ; { find . -name \*.h ! -name \*.c.h ; \
		find . -name \*.c.h -exec sh -c \
		'[ "$$1" != "$${1%.c.h}" ] && [ -e "$${1%.c.h}.h" ] && \
		echo "$$1"' foo {} \; ; } | while read e ; do \
		mkdir -p "../build/include/$$(dirname "$$e")" ; \
		cp "$$PWD/$$e" "../build/include/$$e" ; done

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
		> $@

# 2024-03-08:
# This file is created whenever "inc-dep.mk" ought to be re-made for
# inclusion, and is asynchronously removed after about 3 seconds.
auto/meta-phony.tmp:
	date -u "+%Y-%m-%d T %T %Z" > auto/meta-phony.tmp

inc-dep.mk: auto/meta-phony.tmp
	utils/gen-inc-dep.sh src > inc-dep.mk
	{ sleep 3 ; rm auto/meta-phony.tmp ; } &

# 2024-03-08:
# the include file contains target rules, so it
# must not come before the first rule of this file.
include inc-dep.mk
