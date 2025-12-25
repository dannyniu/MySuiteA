# DannyNiu/NJF, 2023-07-27. Public Domain.

.PHONY: all install uninstall clean distclean

all:
	${MAKE} -f common.mk -f inc-config.mk \
	-f target-dylib-MySuiteA.mk -f build-dylib.mk ${MAKEFLAGS} $@

install uninstall clean:
	${MAKE} -f common.mk -f inc-config.mk \
	-f target-dylib-MySuiteA.mk -f housekeeping.mk ${MAKEFLAGS} $@

distclean: clean
	rm -f inc-*.mk auto/configure[-.]*
