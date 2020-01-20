#!/usr/bin/env python3

import sys, hmac

fp = open("hmac-test-data", "rb")
data = fp.read()
fp.close()

fp = open("hmac-test-key", "rb")
key = fp.read()
fp.close()

x = hmac.new(key, data, digestmod=sys.argv[1]);
print(x.hexdigest())
