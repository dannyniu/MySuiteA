#!/usr/bin/env python3

import sys, hmac, hashlib

fp = open("mac-test-data", "rb")
data = fp.read()
fp.close()

fp = open("mac-test-key", "rb")
key = fp.read()
fp.close()

outlen = str(int(sys.argv[2])//8)

x = eval("hashlib."+sys.argv[1]+"(data, digest_size="+outlen+", key=key)")
print(x.hexdigest())
