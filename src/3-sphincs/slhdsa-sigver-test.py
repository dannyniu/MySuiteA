#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/SLH-DSA-sigVer-FIPS205/internalProjection.json"
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
        elif testgroup['signatureInterface'] == "internal":
            msg = testcase['message']
            ctx = '$'

        pubkey = testcase['pk']
        proc = subprocess.run(
            [ *sys.argv[1:], paramset,
              testcase['hashAlg'],
              testcase['pk'],
              testcase['signature'],
              msg, ctx ])
        if (proc.returncode != 0) == testcase['testPassed']:
            fails+=1
            print("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

if fails > 0: exit("Some test(s) failed!");
else: exit();
