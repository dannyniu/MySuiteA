#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/ML-KEM-encapDecap-FIPS203/internalProjection.json"
fp = open(filepath)
testset = json.load(fp)

for testgroup in testset['testGroups']:
    paramset = testgroup['parameterSet']
    testfunc = testgroup['function']
    if testfunc == "encapsulation":
        for testcase in testgroup['tests']:
            proc = subprocess.run(
                [ *sys.argv[1:], paramset, testfunc,
                  testcase['ek'],
                  testcase['dk'],
                  testcase['c'],
                  testcase['k'],
                  testcase['m'] ])
            if proc.returncode != 0:
                exit("Test Failed for case {} of group {}".format(
                    testcase['tcId'], testgroup['tgId']))
    elif testfunc == "decapsulation":
        for testcase in testgroup['tests']:
            proc = subprocess.run(
                [ *sys.argv[1:], paramset, testfunc,
                  testgroup['dk'],
                  testcase['c'],
                  testcase['k'] ])
            if proc.returncode != 0:
                exit("Test Failed for case {} of group {}".format(
                    testcase['tcId'], testgroup['tgId']))
