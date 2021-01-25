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
finally:
    print("{} tested, {} failed. ".format(cnt, fails))
