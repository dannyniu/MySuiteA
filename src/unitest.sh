#!/bin/sh

#
# -- Begin: The following block may be customized. --

systarget=linux-gnu

CodeChecker="--null--"
if command -v CodeChecker >/dev/null ; then
    # CodeChecker installed.

    CodeChecker=CodeChecker

    # 2022-05-26: add the "--ctu" option when time comes.
    CodeCheckerOpts="\
        --analyzers clangsa --enable-all \
        --disable deadcode.DeadStores"
fi

cflags0="-Wall -Wextra -g -O0"
[ X"$optimize" = Xdebug ] && cflags0="$cflags0 -D ENABLE_HOSTED_HEADERS="
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

#
# -- Begin: mirror to /tmp before testing. --

test_tmpid=UniTest_$(basename "$0" .sh)_$(date +%Y-%m-%d-%H%M%S)_$RANDOM
path_tmpid=/tmp/$test_tmpid
path_src="$(cd "$(dirname $unitest_sh)" ; pwd)"
path_ref="$(cd "$path_src"/../tests ; pwd)"

mkdir $path_tmpid $path_tmpid/bin
ln -s "$path_src" $path_tmpid/src
ln -s "$path_ref" $path_tmpid/tests
cd $path_tmpid/src/"${PWD#$path_src}"

# -- End: mirror to /tmp before testing. --

sysarch=$(uname -m | sed s/arm64/aarch64/g)
sysname=$(uname -s)
hostname=$(uname -n)

test_arch_canrun()
{
    # expected arguments vars:
    # - arch
    # expected setups vars:
    # - sysarch
    # - systarget
    # output var assignments:
    # - ld
    case $arch in
        x86_64) arch_abbrev=amd64 ;;
        aarch64) arch_abbrev=arm64 ;;
        powerpc64) arch_abbrev=ppc64 ;;
        *) arch_abbrev=$arch
    esac

    if [ $sysarch = $arch ] ; then true
    elif ( . /etc/os-release >/dev/null 2>&1 &&
               echo $ID $ID_LIKE | fgrep -q debian ) ; then

        if ! dpkg -l \
             libgcc-\*-dev-${arch_abbrev}-cross \
             libc6-${arch_abbrev}-cross \
             qemu-user >/dev/null 2>&1 ; then false

        elif command -v $arch-$systarget-ld >/dev/null 2>&1
        then ld=$arch-$systarget-ld ; true

        elif command -v ld.lld >/dev/null 2>&1
        then
            ld=ld.lld

            if [ $arch = powerpc64 ] ||
                   [ $arch = sparc64 ]
            then
                echo "$arch unsupported by $($ld --version)"
                false

            else true ; fi
        else false ; fi
    else false ; fi

    ret=$?
    if [ $ret != 0 ] ; then
        echo Skipping 1 non-native architecture test.
        return $ret
    fi
}

test_run_1arch()
(
    # expected arguments vars:
    # - arch
    # expected setups vars:
    # - sysarch
    # - systarget
    # - cc
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

    bin=$(basename "$0" .sh)

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

        qemu_arch=$arch
        qemu_opts=""
        if [ $arch = powerpc64 ] ; then qemu_arch=ppc64 ; fi
        if [ $arch = x86_64 ] ; then qemu_opts="-cpu max" ; fi
        export exec="qemu-$qemu_arch $qemu_opts ./$bin"
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

    cd "$(dirname $unitest_sh)"/../bin
    rm -f *.o *-test
    set -e

    if [ X$UNITEST_STATIC_ANALYZE = Xtrue ] ; then

        if [ X"$CodeChecker" = X--null-- ] ; then
            echo Try installing the \"CodeChecker\" pip package.
            exit 1
        fi

        $CodeChecker log --output ../bin/report-"${arch}-${bin}".json \
                     --build "\$CC -c -ffreestanding $cflags0 $cflags1 \
                     $cflags_common $cflags $srcfiles"

        $CodeChecker analyze $CodeCheckerOpts \
                     ../bin/report-"${arch}-${bin}".json \
                     --output ../bin/reports-"${arch}-${bin}"

    else
        ${CC:-cc} -c -ffreestanding $flags0 $cflags1 \
                  $cflags_common $cflags $srcfiles
    fi

    $ld $ld_opt $ldflags $objfiles -o $bin
    set +e

    if testfunc
    then printf '\033[42;33m%s\033[0m\n' passing ; true
    else printf '\033[41;34m%s\033[0m\n' failing ; false
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
            ( arch=x86_64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=aarch64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=powerpc64
              if test_arch_canrun
              then test_run_1arch
              fi )
            if [ $? -ne 0 ] || [ $ret -ne 0 ] ; then ret=1 ; fi

            ( arch=sparc64
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
    esac

    return $ret;
}
