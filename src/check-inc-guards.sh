#!/bin/sh

cd "$(dirname "$0")"

find . -name \*.h ! -name \*.c.h -exec sh -c '
grep -F -q -i -e "$(basename "$1" | tr .- __)" "$1" || echo "$1"' 'foo' {} \;
