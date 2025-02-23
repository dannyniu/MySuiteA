#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/ML-DSA-sigVer-FIPS204/internalProjection.json"
fp = open(filepath)
testset = json.load(fp)
fails = 0

for testgroup in testset['testGroups']:
    paramset = testgroup['parameterSet']
    for testcase in testgroup['tests']:
        proc = None
        msg = ""
        ctx = ""

        if testgroup['signatureInterface'] == "external":
            msg = testcase['message']
            ctx = testcase['context']
        elif testgroup['externalMu'] is False:
            msg = testcase['message']
            ctx = '#'
        elif testgroup['externalMu'] is True:
            msg = testcase['mu']
            ctx = '$'

        proc = subprocess.run(
            [ *sys.argv[1:], paramset,
              testcase['hashAlg'],
              testcase['pk'],
              testcase['signature'],
              msg, ctx ])

        if (proc.returncode != 0) == testcase['testPassed']:
            exit("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

