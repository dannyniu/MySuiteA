#!/usr/bin/env python3

import json, sys

ip = json.load(sys.stdin)
n = 1

for tg in ip['testGroups']:
    for tc in tg['tests']:
        print(n)
        print("Msg = {}".format(tc['msg']))
        print("MD = {}".format(tc['md']))
        print("")
        n += 1
