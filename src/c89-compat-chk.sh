#!/bin/sh

cd "$(dirname "$0")"/../bin

find ../src -name \*.c ! -name \*-test.c \
     -exec c89 -c -D restrict= -D inline= -Wall -Wextra -Wno-comment {} \;
