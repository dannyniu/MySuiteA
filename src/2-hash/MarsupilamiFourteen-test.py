#!/usr/bin/env python3

import M14, subprocess, secrets, os, re

fails = 0

for mlen in (23**i for i in range(5)):
    for clen in (43**j for j in range(3)):
        m = secrets.token_bytes(mlen)
        c = secrets.token_bytes(clen)
        p = subprocess.Popen(
            re.split(r'\s+', os.getenv("exec"))+[str(mlen)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        ref = M14.MarsupilamiFourteen(m, c, 256)
        p.stdin.write(m);
        p.stdin.write(c);
        p.stdin.close();
        res = p.stdout.read()
        p.terminate()
        if ref != res:
            fails+=1
            print("test failed with mlen={} and clen={}".format(mlen, clen))

if fails > 0: exit("Some tests failed")
else: exit()
