#!/bin/sh

# I was going to use SIGCHLD, but some quirks (with bash I presume)
# convinced me to devise some other convoluted scheme using SIGUSR1.

# This script runs all tests in MySuiteA (not including checks).

if [ X"$1" = X-1 ] ; then # run 1 test.
    shift
    printf '%s\n' "$1"
    ./"$1" >../bin/"$(basename "$1" .sh)".log 2>&1
    kill -USR1 "$2" || echo "$1"
    exit
fi

cd "$(dirname "$0")"
self="./$(basename "$0")"

set $(find . -name \*-test.sh | sort)
sem=$#

cmd='# script literal for the main command
if [ $# -gt 0 ] ; then
    "$self" -1 "$1" $$ &
    shift
fi ;'

trap "sem=\$((sem-1)) ; $cmd" USR1
for c in 1 2 3 4 5 6 ; do eval "$cmd" ; done
wait
while [ $sem -gt 0 ] ; do sleep 2 ; done
wait
