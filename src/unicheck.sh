#!/bin/sh

if ! command -v CodeChecker >/dev/null ; then
    echo 'CodeChecker not found. Try installing the "CodeChecker" pip package.'
fi

build_only=yes
arch_native=$(uname -m | sed s/arm64/aarch64/g)
: "${want_srcset:=Plain C}" "${want_arch:=$arch_native}"

export want_srcset want_arch build_only

CheckerOpts="\
--analyzers clangsa --enable-all \
--disable deadcode.DeadStores
--disable security.insecureAPI.DeprecatedOrUnsafeBufferHandling"

if ! grep -q "srcset=.*$want_srcset" "$1" ; then
    echo
    echo '**WARNING**'
    echo The source set "\"$want_srcset\"" is \
         not found in the test script: "\"$1\"".
    echo Consider specify one explicitly.
    echo
fi

auto_path="$(dirname "$0")"/../auto
reports="$auto_path"/reports_"$(basename $1 .sh)"

CodeChecker check --build "$*" --output "$reports" --clean $CheckerOpts
CodeChecker parse --export html --output "$reports"_html "$reports"
