#!/usr/bin/env python3

import json
import subprocess, sys, os

filepath = "../tests/ML-DSA-sigGen-FIPS204/internalProjection.json"
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

env = dict(os.environ)
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
        elif testgroup['externalMu'] is False:
            msg = testcase['message']
            ctx = '#'
        elif testgroup['externalMu'] is True:
            msg = testcase['mu']
            ctx = '$'

        if detsign:
            proc = subprocess.Popen(
                [ *sys.argv[1:], paramset,
                  testcase['hashAlg'],
                  testcase['sk'],
                  msg, ctx ],
                text=True, env=env, stdout=subprocess.PIPE)
        else:
            rnd = testcase['rnd']
            proc = subprocess.Popen(
                [ *sys.argv[1:], paramset,
                  testcase['hashAlg'],
                  testcase['sk'],
                  msg, ctx,
                  rnd ],
                text=True, env=env, stdout=subprocess.PIPE)

        sig = proc.stdout.read().strip()
        if sig != testcase['signature']:
            fails+=1
            #dump(sig)
            #dump(testcase['signature'])
            print("Test Failed for case {} of group {}".format(
                testcase['tcId'], testgroup['tgId']))

if fails > 0: exit("Some test(s) failed!");
else: exit();
