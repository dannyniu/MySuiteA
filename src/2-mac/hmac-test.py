#!/usr/bin/env python3

import sys, hmac

fp = open("mac-test-key", "rb")
key = fp.read()
fp.close()

x = hmac.new(key, digestmod=sys.argv[1]);
fd0 = sys.stdin.buffer

while True:
    s = fd0.read(512)
    if len(s): x.update(s)
    else: break

print(x.hexdigest())
