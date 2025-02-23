#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/ML-KEM-keyGen-FIPS203/internalProjection.json"
fp = open(filepath)
testset = json.load(fp)

for testgroup in testset['testGroups']:
    paramset = testgroup['parameterSet']
    for testcase in testgroup['tests']:
        proc = subprocess.Popen(
            [ *sys.argv[1:], paramset, testcase['z']+testcase['d']],
            text=True, stdout=subprocess.PIPE)
        keypair = proc.stdout.read().strip()
        if keypair != testcase['dk'] + ":" + testcase['ek']:
            print(keypair)
            print(testcase['dk']+":"+testcase['ek'])
            exit("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

