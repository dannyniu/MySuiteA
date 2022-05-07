#!/bin/sh

# This script runs all tests in MySuiteA (excluding checks).

if [ X"$1" = X-1 ] ; then # run 1 test.
    shift
    printf '%s\n' "$1"
    ./"$1" >../bin/"$(basename "$1" .sh)".log 2>&1
    exit
fi

cd "$(dirname "$0")"
self="./$(basename "$0")"

set $(find . -name \*-test.sh | sort)

pvec="1 2 3 4 5 6"
for pv in $pvec ; do eval "pid${pv}=ready" ; done

while [ $# -gt 0 ] ; do
    for pv in $pvec ; do
        if eval test "\$pid${pv}" = done ; then
            continue
        elif
            eval test "\$pid${pv}" = ready ||
                ! eval kill -0 "\$pid${pv}" 2>/dev/null
        then
            if [ $# -gt 0 ] ; then
                "$self" -1 "$1" &
                eval "pid${pv}=$!"
                shift
            else
                eval "pid${pv}=done"
            fi
        fi
    done
    sleep 1
done

for pv in $pvec ; do
    if eval test "\$pid${pv}" != done ; then
        while eval kill -0 "\$pid${pv}" 2>/dev/null
        do sleep 2 ; done
        eval wait "\$pid${pv}"
        eval "pid${pv}=done"
    fi
done

echo omnitest: exiting
exit
