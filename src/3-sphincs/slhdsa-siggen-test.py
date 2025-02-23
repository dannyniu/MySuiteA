#!/usr/bin/env python3

import json
import subprocess, sys

filepath = "../tests/SLH-DSA-sigGen-FIPS205/internalProjection.json"
fp = open(filepath)
testset = json.load(fp)
fails = 0

def dump(s):
    print("-- begin --")
    while len(s) > 64:
        o = s[0:64]
        print(o)
        s = s[64:]
    print(s)
    print("-- end --")

for testgroup in testset['testGroups']:
    paramset = testgroup['parameterSet']
    detsign = testgroup['deterministic']

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

        if detsign:
            continue
            proc = subprocess.Popen(
                [ *sys.argv[1:], paramset,
                  testcase['hashAlg'],
                  testcase['sk'],
                  msg, ctx ],
                text=True, stdout=subprocess.PIPE)
        else:
            rnd = testcase['additionalRandomness']
            proc = subprocess.Popen(
                [ *sys.argv[1:], paramset,
                  testcase['hashAlg'],
                  testcase['sk'],
                  msg, ctx,
                  rnd ],
                text=True, stdout=subprocess.PIPE)
        sig = proc.stdout.read().strip()
        if sig != testcase['signature']:
            fails+=1
            #dump(sig)
            #dump(testcase['signature'])
            exit("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

if fails > 0: exit("Some test(s) failed!");
else: exit();
