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

cc=clang
if ! command -v $cc >/dev/null ; then
    echo The \"clang\" compiler is not available, falling back to '"$CC"'
    cc="$CC"
fi

cc="$scan_build $scan_build_opt $cc"
cflags0="-Wall -Wextra -g -O0"
[ X"$optimize" = Xdebug ] && cflags0="$cflags0 -D ENABLE_HOSTED_HEADERS"
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

case $arch in
    aarch64) arch_abbrev=arm64 ;;
    powerpc64) arch_abbrev=ppc64 ;;
    *) arch_abbrev=$arch
esac

if [ $sysarch = $arch ] ; then true
elif ( . /etc/os-release && echo $ID $ID_LIKE | fgrep -q debian ) ; then
    
    if ! dpkg -l \
         libgcc-\*-dev-${arch_abbrev}-cross \
         libc-dev-${arch_abbrev}-cross \
         qemu-user ; then false
                          
    elif command -v $arch-$systarget-ld
    then ld=$arch-$systarget-ld ; true
         
    elif command -v ld.lld
    then
        ld=ld.lld
        
        if [ $arch = powerpc64 ] ; then
            echo As of version 10.0.0:
            echo LLVM LLD has not supported big-endian PowerPC64.
            false
            
        elif [ $arch = sparc64 ] ; then
            echo As of version 10.0.0:
            echo LLVM LLD has not supported \"elf64-sparc\"
            echo as an output format.
            false
            
        else true ; fi
    else false ; fi
else false ; fi >/dev/null 2>&1

if [ $? != 0 ] ; then
    echo Skipping 1 non-native architecture test.
    exit 0
fi

# routinal notification info.
echo "======== Test Name: $bin ; ${arch} / ${srcset} ========"

if [ $sysarch = $arch ] ; then
    cflags1=""
    ld=cc
    ld_opt=""
    export exec=./$bin

else
    last(){ shift $(( $# - 1 )) ; echo "$1" ; }
    UsrArchIncPath=/usr/$arch-$systarget/include
    UsrArchLibPath=/usr/$arch-$systarget/lib
    UsrArchGccLibPath=$(last /usr/lib/gcc-cross/$arch-$systarget/*)
    
    cflags1="-target $arch-$systarget -isystem $UsrArchIncPath"
    
    ld_opt="
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
$ld $ld_opt $objfiles -o $bin
set +e

if testfunc
then printf '\033[42m\033[33m%s\033[0m\n' passing
else printf '033[41m\033[34%s\033[0m\n' failing
fi

#rm $objfiles $bin
