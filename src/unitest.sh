#!/bin/sh

#
# -- Begin: The following block may be customized. --

systarget=linux-gnu

cflags0="-Wall -Wextra -g -O0"
:  ${optimize:=true}
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

. "$(dirname $unitest_sh)"/uniconf.sh.inc

# -- End: customizable block; --

#
# -- Begin: mirror to /tmp before testing. --

test_tmpid=UniTest_$(basename "$0" .sh)_$(date +%Y-%m-%d-%H%M%S)_$RANDOM
path_tmpid=/tmp/$test_tmpid
path_src="$(cd "$(dirname $unitest_sh)" ; pwd)"
path_ref="$(cd "$path_src"/../tests ; pwd)"
link_auto="$(cd "$path_src"/../auto ; pwd)"

rm -f "$link_auto"/UniTest
ln -s $path_tmpid "$link_auto"/UniTest
mkdir $path_tmpid $path_tmpid/auto
ln -s "$path_src" $path_tmpid/src
ln -s "$path_ref" $path_tmpid/tests
cd $path_tmpid/src/"${PWD#$path_src}"

# -- End: mirror to /tmp before testing. --

sysarch=$(uname -m | sed s/arm64/aarch64/g)
sysname=$(uname -s)

find_arch_cc()
{
    # expected arguments var:
    # - arch
    # - systarget

    if command -v clang >/dev/null 2>&1
    then echo "clang -target $arch-$systarget"

    elif command -v $arch-$systarget-gcc >/dev/null 2>&1
    then echo "$arch-$systarget-gcc"

    fi
}

find_arch_ld()
{
    # expected arguments var:
    # - arch
    # - systarget

    if command -v $arch-$systarget-ld >/dev/null 2>&1
    then echo $arch-$systarget-ld

    elif command -v ld.lld >/dev/null 2>&1
    then
        case $arch in
            powerpc64|sparc64|riscv64)

                # lld happens to support 32-bit powerpc.
                # but it's having a bit of trouble with
                # riscv64 as of 2022-10-02.

                echo "$arch unsupported by $(ld.lld --version)" >&2
                ;;

            *)
                # assume it may work for the target, even though
                # it's most likely not going to work.

                echo ld.lld
                ;;
        esac
    fi
}

test_arch_canrun()
{
    # expected arguments vars:
    # - arch
    # expected setups vars:
    # - sysarch
    # - systarget
    # output var assignments:
    # - target_ld
    # - target_cc
    case $arch in
        i686) arch_abbrev=i386 ;;
        x86_64) arch_abbrev=amd64 ;;
        aarch64) arch_abbrev=arm64 ;;
        powerpc64) arch_abbrev=ppc64 ;;
        powerpc64le) arch_abbrev=ppc64el ;;
        *) arch_abbrev=$arch
    esac

    target_ld=""
    target_cc=""

    if [ $sysarch = $arch ] ; then
        target_ld=cc
        target_cc=cc

    elif ( . /etc/os-release >/dev/null 2>&1 &&
               echo $ID $ID_LIKE | grep -F -q debian ) ; then

        # Debian/Ubuntu -like distributions.

        if dpkg -l qemu-user \
                libgcc-\*-dev-${arch_abbrev}-cross \
                libc6-${arch_abbrev}-cross \
                >/dev/null 2>&1

        then
            target_cc=$(find_arch_cc)
            target_ld=$(find_arch_ld)

        fi
    fi

    if [ ! "$target_cc" ] || [ ! "$target_ld" ] ; then
        echo Skipping 1 non-native architecture test. >&2
        false
    else : ; fi
}

test_run_1arch()
(
    # expected arguments vars:
    # - arch
    # expected setups vars:
    # - sysarch
    # - systarget
    # - target_cc
    # - target_ld
    # - cflags0

    # 2022-02-14: 2 notes.
    #
    # 1. The "src_common" variable had been imported here so that test scripts
    #    can avoid using function commands such as "vsrc". The source code
    #    files set is assembled from "src_common" (when available) and "src",
    #    which would define additional source code files when "src_common" is
    #    already defined.
    #
    # 2. The "cflags_common" variable is imported whenever test scripts define
    #    one. This variable contain compilation flags that is intended to be
    #    repeated among all test variants within a test script. The "cflags"
    #    flag now serves the purpose of defining variant-specific compilation
    #    flags for a test.

    : ${srcset:='(unset:${srcset})'}
    : ${src_common:=""}
    : ${src:?Variable unspecified: src}
    : ${arch:?Variable unspecified: arch}
    : ${cflags_common:=""}
    : ${cflags:=""}
    : ${ldflags_common:=""}
    : ${ldflags:=""}

    if [ X"${want_srcset:-$srcset}" != X"$srcset" ] ||
           [ X"${want_arch:-$arch}" != X"$arch" ]
    then return ; fi

    bin=$(basename "$0" .sh)

    # routinal notification info.
    echo "======== Test Name: $bin ; ${arch} / ${srcset} ========"

    if [ $sysarch = $arch ] ; then
        cflags1=""
        ld_opts=""
        export exec=./$bin

    else
        last(){ shift $(( $# - 1 )) ; echo "$1" ; }
        UsrArchIncPath=/usr/$arch-$systarget/include
        UsrArchLibPath=/usr/$arch-$systarget/lib
        UsrArchGccLibPath=$(last /usr/lib/gcc-cross/$arch-$systarget/*)

        cflags1="-isystem $UsrArchIncPath"

        dyld=$(set $(find $UsrArchLibPath* -type f |
                         grep -E '/ld([^a-zA-Z].*)?\.so(.[1-9])?$' |
                         sort) ; echo $1)

        ld_opts="\
          $UsrArchLibPath/crt[1in].o
          $UsrArchGccLibPath/crtbegin.o
          $UsrArchGccLibPath/crtend.o
          -L$UsrArchLibPath
          -L$UsrArchGccLibPath
          -lc"

        qemu_arch=$arch
        qemu_opts=""
        if [ $arch = i686 ] ; then qemu_arch=i386 ; fi
        if [ $arch = x86_64 ] ; then qemu_opts="-cpu max" ; fi
        if [ $arch = powerpc ] ; then qemu_arch=ppc ; fi
        if [ $arch = powerpc64 ] ; then qemu_arch=ppc64 ; fi
        if [ $arch = powerpc64le ] ; then qemu_arch=ppc64le ; fi
        export exec="qemu-${qemu_arch} $qemu_opts $dyld ./$bin"
        export LD_LIBRARY_PATH=$UsrArchLibPath:$LD_LIBRARY_PATH
    fi

    if [ $sysname = Linux ] ; then
        cflags="$cflags -fPIC"
    fi

    srcdir=../src
    basedir=$srcdir/$(basename "$PWD")
    srcfiles=""
    objfiles=""
    for s in $src_common $src ; do
        b=$(basename $s)
        if [ $s = $b ]
        then srcfiles="$srcfiles $basedir/$s"
        else srcfiles="$srcfiles $srcdir/$s"
        fi ; objfiles="$objfiles ${b%.*}.o"
    done

    cd "$(dirname $unitest_sh)"/../auto
    rm -f *.o *-test
    set -e

    ${CC:-$target_cc} -c $cflags_proj $cflags0 $cflags1 \
              $cflags_common $cflags $srcfiles

    ${LD:-$target_ld} $ld_opts $ldflags_common $ldflags $objfiles -o $bin
    set +e

    if [ X"$build_only" != Xyes ] ; then
        if testfunc
        then printf '\033[42;33m%s\033[0m\n' passing ; true
        else printf '\033[41;34m%s\033[0m\n' failing ; false
        fi
    fi

    #rm $objfiles $bin
)

# 2022-02-19:
# The functions "shortrand" and "randblob" had been added to lessen
# the verbosity of tests involving randomly generated long test vectors.

shortrand()
{
    python3 -c 'import secrets; x=secrets.randbits(5); print(str(x*x*x))'
}

randblob()
{
    len=$1
    bs=512
    cnt=$((len / bs))
    2>/dev/null dd if=/dev/urandom count=$cnt bs=$bs
    2>/dev/null dd if=/dev/urandom count=1 bs=$((len - bs * cnt))
}

ret=0

tests_run()
{
    case $arch_family in
        defaults)
            # 2022-09-30:
            # The default set was:
            # x86_64, aarch64, powerpc64, and sparc64.
            # The sparc64 architecture is having segfault which I have
            # little resource to debug, and is being removed. The other
            # major reason to change the default set of architectures is
            # to ensure the completeness of test coverage, on both big-
            # and little- endian and 32- and 64- bit architectures.
            # Therefore, the default set now is:
            # i686, x86_64, aarch64, powerpc, and powerpc64.

            ( arch=i686
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( if { : ; arch=aarch64 ; [ X"$sysarch" = X"$arch" ] &&
                                          test_arch_canrun ; } ||
                     { arch=x86_64  ; test_arch_canrun ; } ||
                     { arch=aarch64 ; test_arch_canrun ; }
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=powerpc
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=powerpc64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi
            ;;

        # 2022-02-19:
        # Specifying $arch_family allows (possibly multiple)
        # $arch to be adapt to different data models
        # (e.g. word lengths) within the same architecture.

        x86)
            ( arch=x86_64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi
            ;;

        arm)
            ( arch=aarch64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi
            ;;

        ppc)
            ( arch=powerpc64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=powerpc64le
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi
            ;;

        +*)
            ( arch=${arch_family#+}
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi
            ;;
    esac

    return $ret;
}
