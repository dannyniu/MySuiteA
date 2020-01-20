#!/usr/bin/env python3

import hashlib, sys

x = hashlib.new(sys.argv[1])
fd0 = sys.stdin.buffer

while True:
    s = fd0.read(512)
    if len(s): x.update(s)
    else: break

print(x.hexdigest())
