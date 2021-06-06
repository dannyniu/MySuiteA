#!/bin/sh

qemu_exec() {
    a=$1 ; shift
    if [ $a = powerpc64 ] ; then a=ppc64 ; fi # kludge. 
    qemu-$a "$@"
}

# -- Begin: The following block may be customized. --

systarget=linux-gnu
if command -v scan-build >/dev/null ; then
    # scan-build installed. 
    scan_build=scan-build
    regex='^[^[:alnum:].]*\([[:alnum:].]*\)[^[:alnum:].].*$'
    checkers="$(
        $scan_build --help-checkers-verbose |
            sed -n "s/$regex/--enable-checker \1/p" |
            fgrep . )"
    scan_build_opt="$checkers"
else
    echo Try installing the \"scan-build\" pip package.
    exit 1
fi
cc="$scan_build $scan_build_opt clang"
cflags0="-Wall -Wextra -g -O0"
[ X"$optimize" = Xtrue ] && cflags0="-Wall -Wextra -O"

# Note 2020-02-18 regarding removal of "-Weverything" option:
# refer to the following excerpt from the Clang Compiler User's Manual:
#
# > Since -Weverything enables every diagnostic, we generally
# > don't recommend using it. -Wall -Wextra are a better choice for
# > most projects. Using -Weverything means that updating your compiler
# > is more difficult because you're exposed to experimental diagnostics
# > which might be of lower quality than the default ones. If you do
# > use -Weverything then we advise that you address all new compiler
# > diagnostics as they get added to Clang, either by fixing everything
# > they find or explicitly disabling that diagnostic with its
# > corresponding -Wno- option.
#

# -- End; --

: ${src:?Variable unspecified: src}
: ${bin:?Variable unspecified: bin}
: ${arch:?Variable unspecified: arch}
: ${cflags:=""}

sysarch=$(uname -m | sed s/arm64/aarch64/g)
sysname=$(uname -s)
hostname=$(uname -n)

if
    [ $sysarch != $arch ] && ! (
        . /etc/os-release &&
            echo $ID $ID_LIKE | fgrep -q ubuntu &&
            dpkg -l clang gcc-${arch}-linux-gnu qemu-user
    ) >/dev/null 2>&1
then
    echo Skipping 1 non-native architecture test.
    exit
fi

# routinal notification info.
echo ======== Test Name: $bin ========
echo "${arch} / ${srcset}"

if [ $sysarch = $arch ] ; then
    UsrArchIncPath=/usr/include
    cflags1=""
    ld=cc
    export exec=./$bin

else
    last(){ shift $(( $# - 1 )) ; echo "$1" ; }
    UsrArchIncPath=/usr/$arch-$systarget/include
    UsrArchLibPath=/usr/$arch-$systarget/lib
    UsrArchGccLibPath=$(last /usr/lib/gcc-cross/$arch-$systarget/*)
    
    cflags1="-target $arch-$systarget -isystem $UsrArchIncPath"
    ld="
      $arch-$systarget-ld
      -dynamic-linker
      $UsrArchLibPath/ld-*.so
      $UsrArchLibPath/crt[1in].o
      $UsrArchGccLibPath/crtbegin.o
      $UsrArchGccLibPath/crtend.o
      -L$UsrArchLibPath
      -L$UsrArchGccLibPath
      -lc -lgcc -lgcc_s
    "
    
    export exec="qemu_exec $arch ./$bin"
    export LD_LIBRARY_PATH=$UsrArchLibPath:$LD_LIBRARY_PATH
fi

if [ $sysname = Linux ] ; then
    cflags="$cflags -fPIC"
fi

srcdir=../src
basedir=$srcdir/$(basename "$PWD")
srcfiles=""
objfiles=""
for s in $src ; do
    b=$(basename $s)
    if [ $s = $b ]
    then srcfiles="$srcfiles $basedir/$s"
    else srcfiles="$srcfiles $srcdir/$s"
    fi ; objfiles="$objfiles ${b%.*}.o"
done

cd "$(dirname $unitest_sh)"/../bin
rm -f *.o *-test
set -e
$cc -c -ffreestanding $cflags0 $cflags1 $cflags $srcfiles
$ld $objfiles -o $bin
set +e

testfunc
#rm $objfiles $bin
