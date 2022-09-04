#!/usr/bin/env python3

import json, sys

if len(sys.argv) == 2:
    for i in range(int(sys.argv[1])):
        sys.stdout.buffer.write(bytes([i % 251]))
    exit()

fp = open("../tests/blake3-test_vectors.json")
obj = json.load(fp)
fp.close()

if len(sys.argv) == 1:
    for case in obj['cases']:
        print(case['input_len'])
    exit()

if len(sys.argv) == 3:
    for case in obj['cases']:
        if case['input_len'] == int(sys.argv[1]):
            print(case[sys.argv[2]])
            break
    exit()
