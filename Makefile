# DannyNiu/NJF, 2023-07-27. Public Domain.

.PHONY: all install uninstall clean distclean

all:; ${MAKE} -f build.mk ${MAKEFLAGS} $@
install uninstall clean distclean:
	${MAKE} -f housekeeping.mk ${MAKEFLAGS} $@
