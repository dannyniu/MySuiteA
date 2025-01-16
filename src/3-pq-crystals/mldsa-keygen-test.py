#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/ML-DSA-keyGen-FIPS204/internalProjection.json"
fp = open(filepath)
testset = json.load(fp)

for testgroup in testset['testGroups']:
    paramset = testgroup['parameterSet']
    for testcase in testgroup['tests']:
        proc = subprocess.Popen(
            [ *sys.argv[1:], paramset, testcase['seed'] ],
            text=True, stdout=subprocess.PIPE)
        keypair = proc.stdout.read().strip()
        if keypair != testcase['sk'] + ":" + testcase['pk']:
            print(keypair)
            print(testcase['sk']+":"+testcase['pk'])
            exit("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

