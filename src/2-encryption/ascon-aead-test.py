#!/usr/bin/env python3

import json, sys, subprocess

ip = json.load(sys.stdin)

for tg in ip['testGroups']:
    for tc in tg['tests']:
        match tg['direction']:

            case "encrypt":
                key = tc['key']
                if tg['supportsNonceMasking']:
                    key += tc['secondKey']

                proc = subprocess.Popen([
                    *sys.argv[1:], "enc",
                    tc['ad'], tc['pt'], key, tc['nonce'], str(tc['tagLen'])
                ], text=True, stdout=subprocess.PIPE)
                ct = proc.stdout.read().strip("\n").lower()
                ref = '{} {}'.format(tc['ct'], tc['tag']).lower()
                if not ct.startswith(ref):
                    exit("Enc Failed for tcId {} of tgId {}.".format(
                        tc['tcId'], tg['tgId']))

            case "decrypt":
                key = tc['key']
                if tg['supportsNonceMasking']:
                    key += tc['secondKey']

                proc = subprocess.Popen([
                    *sys.argv[1:], "dec",
                    tc['ad'], tc['ct'], key, tc['nonce'], tc['tag']
                ], text=True, stdout=subprocess.PIPE)

                if (proc.wait() != 0) == tc['testPassed']:
                    print(proc.returncode)
                    exit("Tag Failed for case {} of group {}".format(
                        tc['tcId'], tg['tgId']))

                if proc.returncode != 0:
                    continue

                w = proc.stdout.read().strip("\n").lower()
                if w != tc['pt'].lower():
                    exit("Dec Failed for tcId {} of tgId {}.".format(
                        tc['tcId'], tg['tgId']))
