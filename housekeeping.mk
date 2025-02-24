# DannyNiu/NJF, 2024-07-27. Public Domain.

include common.mk
include objects.mk

include inc-config.mk

.PHONY: all install uninstall clean distclean

all:;:

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
	rm -f ${OBJS_GROUP_ALL} ${OBJS_GROUP_WITH_ADDITION}

distclean: clean
	rm -f inc-*.mk auto/configure[-.]*
