#!/usr/bin/env python3

import sys, hashlib

fp = open("mac-test-key", "rb")
key = fp.read()
fp.close()

outlen = str(int(sys.argv[2])//8)
x = eval("hashlib."+sys.argv[1]+"(digest_size="+outlen+", key=key)")
fd0 = sys.stdin.buffer

while True:
    s = fd0.read(512)
    if len(s): x.update(s)
    else: break

print(x.hexdigest())
