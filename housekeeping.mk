# DannyNiu/NJF, 2025-12-25. Public Domain.

.PHONY: all install uninstall clean distclean

all:;:

install:
	mkdir -p ${libdir}/pkgconfig ${includedir}
	cp build/"${ProductName}".pc ${libdir}/pkgconfig
	cp build/"${ProductName}.${FILE_EXT}" ${libdir}
	@ if [ -e ${includedir}/${LibraryName} ] ; then \
		echo include headers director exists! ; \
		false ; \
	else cp -R -L build/include ${includedir}/${LibraryName} ; fi

uninstall:
	rm ${libdir}/pkgconfig/"${ProductName}".pc
	rm ${libdir}/"${ProductName}.${FILE_EXT}"
	rm -R ${includedir}/${LibraryName}

clean:
	rm -f build/"${ProductName}.${FILE_EXT}"
	rm -f build/"${ProductName}.pc"
	rm -Rf build/include
	rm -f ${INPUT_OBJECTS}
