#!/usr/bin/env python3

cnt = 0
fails = 0
coprime = 0

def egcd(z, a):
    global coprime
    i = a
    j = z
    y2 = 0
    y1 = 1
    while j > 0:
        (quo, rem) = divmod(i, j)
        y2 -= y1 * quo
        i = j
        j = rem
        (y2, y1) = (y1, y2)
    if i == 1:
        return y2 & ((1 << 128) - 1)
    else:
        coprime += 1
        return None

try:
    while True:
        s = input()
        if not s: break
        cnt += 1
        if not eval(s):
            fails += 1
            print("wrong: "+s);
except EOFError: pass

print("{} tested, {} failed, {} coprime. ".format(cnt, fails, coprime))
if fails == 0: raise SystemExit()
else: raise SystemExit("Some Tests Failed")
