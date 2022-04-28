#!/usr/bin/env python3

global p
p = (1 << 255) - 19

def X25519(k, u):
    global p
    print(str(k))
    print(str(u))
    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0
    for t in (255 - i - 1 for i in range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            (x2, x3) = (x3, x2)
            (z2, z3) = (z3, z2)
        swap = kt
        A = (x2 + z2) % p
        B = (x2 - z2) % p
        AA = (A * A) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = (DA + CB) % p
        x3 = (x3 * x3) % p
        z3 = (DA - CB) % p
        z3 = (x1 * z3 * z3) % p
        x2 = (AA * BB) % p
        z2 = (AA + 121665 * E) % p
        z2 = (E * z2) % p
    if swap:
        (x2, x3) = (x3, x2)
        (z2, z3) = (z3, z2)
    return hex((x2 * pow(z2, p-2, p)) % p)

cnt = 0
fails = 0

if __name__ == "__main__":
    try:
        while True:
            s = input()
            if not s: break
            cnt += 1
            # if not eval(s):
            #     fails += 1
            #     print("wrong: "+s);
    except EOFError: pass
    
    print("{} tested, {} failed. ".format(cnd, fails))
    if fails == 0: raise SystemExit()
    else: raise SystemExit("Some Tests Failed")
