# DannyNiu/NJF, 2022-10-02. Public Domain.

testfunc() {
    failcount=0
    kmax=5
    mmax=13
    for algo in $hash_algos ; do
        kcnt=0
        while [ $kcnt -lt $kmax ] ; do
            mcnt=0
            while [ $mcnt -lt $mmax ] ; do
                echo $algo $(($(shortrand) % 64)) $(shortrand)
                mcnt=$((mcnt + 1))
            done
            kcnt=$((kcnt+1))
        done
    done | while
        rm -f mac-test-ref mac-test-result mac-test-key mac-test-data
        if ! read algo klen mlen ; then
            echo "$failcount test(s) failed."
            if [ $failcount -gt 0 ]
            then return 1
            else return 0
            fi
        else true ; fi
    do
        randblob $klen > mac-test-key
        randblob $mlen > mac-test-data

        ../src/2-mac/hmac-test.py $algo < mac-test-data > mac-test-ref &
        $exec $algo < mac-test-data > mac-test-result #&
        wait

        if [ "$(cat mac-test-ref)" = "$(cat mac-test-result)" ] ; then
            : echo Test succeeded for $algo klen=$klen mlen=$mlen
        else
            echo Test failed for $algo klen=$klen mlen=$mlen!
            failcount=$((failcount+1))
            suffix=$(date +%Y-%m-%d-%H%M%S)-$failcount
            mv mac-test-key mac-test-key-$suffix
            mv mac-test-data mac-test-data-$suffix
        fi
    done
}
