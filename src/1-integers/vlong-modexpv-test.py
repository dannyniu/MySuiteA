#!/usr/bin/env python3

cnt = 0;
fails = 0;

try:
    while True:
        s = input()
        if not s: break
        cnt += 1
        if not eval(s):
            fails += 1
            print("wrong: "+s);
except EOFError: pass

print("{} tested, {} failed. ".format(cnt, fails))
if fails == 0: raise SystemExit()
else: raise SystemExit("Some Tests Failed")
