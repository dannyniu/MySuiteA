#!/bin/sh

qemu_exec() {
    a=$1 ; shift
    if [ $a = powerpc64 ] ; then a=ppc64 ; fi # kludge. 
    qemu-$a "$@"
}

# -- Begin: The following block may be customized. --

systarget=linux-gnu
if command -v scan-build ; then
    # scan-build installed. 
    scan_build=scan-build
    scan_build_opt=""
else
    # Assume it's my Mac Mini. 
    scan_build=~/Applications/checker-279/bin/scan-build
    scan_build_opt="--use-cc /usr/bin/clang --use-analyzer Xcode"
fi
cc="$scan_build $scan_build_opt clang"
cflags0="-Wall -Wextra -Weverything -g -O0"

# -- End; --

: ${src:?Variable unspecified: src}
: ${bin:?Variable unspecified: bin}
: ${arch:?Variable unspecified: arch}
: ${cflags:=""}

sysarch=$(uname -m)
sysname=$(uname -s)
hostname=$(uname -n)

if [ $sysarch != $arch ] && [ $hostname != uniarch ] ; then
    echo Skipping 1 non-native architecture test.
    exit
fi

if [ $sysarch = $arch ] ; then
    UsrArchIncPath=/usr/include
    cflags1=""
    ld=cc
    export exec=./$bin

else
    last(){ shift $(( $# - 1 )) ; echo "$1" ; }
    UsrArchIncPath=/usr/$arch-$systarget/include
    UsrArchLibPath=/usr/$arch-$systarget/lib
    UsrArchGccLibPath=`last /usr/lib/gcc-cross/$arch-$systarget/*`
    
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
rm -f *.o
set -e
$cc -c -ffreestanding $cflags0 $cflags1 $cflags $srcfiles
$ld $objfiles -o $bin
set +e

testfunc
#rm $objfiles $bin
