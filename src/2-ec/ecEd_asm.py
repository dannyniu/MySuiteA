#!/usr/bin/env python3

import sys, secrets
sys.path += ["../src/1-integers", "../1-integers"]

from int2os import *

p = (1 << 255) - 19
a = -1
d_over = -121665
d_under = 121666
d = d_over * pow(d_under, p-2, p) % p

def point_add_rfc(X1, Y1, T1, Z1, X2, Y2, T2, Z2):
    A = (Y1-X1)*(Y2-X2)
    B = (Y1+X1)*(Y2+X2)
    C = T1*2*d*T2
    D = Z1*2*Z2
    E = B-A
    F = D-C
    G = D+C
    H = B+A
    X3 = E*F
    Y3 = G*H
    T3 = E*H
    Z3 = F*G
    return (X3, Y3, T3, Z3)

def point_add_ref(x1, y1, t1, z1, x2, y2, t2, z2):
    x1y2 = x1 * y2 % p
    x2y1 = x2 * y1 % p
    x1x2 = x1 * x2 % p
    y1y2 = y1 * y2 % p
    z1z2 = z1 * z2 % p
    t1t2 = t1 * t2 % p
    x3 = (x1y2 +     x2y1) * (z1z2 - d * t1t2) % p
    y3 = (y1y2 - a * x1x2) * (z1z2 + d * t1t2) % p
    t3 = (y1y2 - a * x1x2) * (x1y2 + x2y1) % p
    z3 = (z1z2 - d * t1t2) * (z1z2 + d * t1t2) % p
    return (x3, y3, t3, z3)

def point_add_ref_smalld(x1, y1, t1, z1, x2, y2, t2, z2):
    x1y2 = x1 * y2 % p
    x2y1 = x2 * y1 % p
    x1x2 = x1 * x2 % p
    y1y2 = y1 * y2 % p
    z1z2 = z1 * z2 % p
    t1t2 = t1 * t2 % p
    x3 = (x1y2 +     x2y1) * (z1z2 * d_under - d_over * t1t2) % p
    y3 = (y1y2 - a * x1x2) * (z1z2 * d_under + d_over * t1t2) % p
    t3 = (y1y2 - a * x1x2) * (x1y2 + x2y1) % p
    z3 = (z1z2 * d_under - d_over * t1t2) * (z1z2 * d_under + d_over * t1t2) % p
    x3 = x3 * d_under % p
    y3 = y3 * d_under % p
    t3 = t3 * d_under * d_under % p
    return (x3, y3, t3, z3)

def point_add_blueprint(x1, y1, t1, z1, x2, y2, t2, z2):
    x1y2 = x1 * y2 % p
    x2y1 = x2 * y1 % p
    x1x2 = x1 * x2 % p
    y1y2 = y1 * y2 % p
    z1z2 = z1 * z2 % p
    t1t2 = t1 * t2 % p
    s = (x1y2 + x2y1) % p
    t = (y1y2 - a * x1x2) % p
    u = (z1z2 * d_under - d_over * t1t2) % p
    v = (z1z2 * d_under + d_over * t1t2) % p
    x3 = s * u % p
    t3 = t * s % p
    y3 = t * v % p
    z3 = u * v % p
    x3 = x3 * d_under % p
    y3 = y3 * d_under % p
    t3 = t3 * d_under * d_under % p
    return (x3, y3, t3, z3)

def point_add_asm(x1, y1, t1, z1, x2, y2, t2, z2):
    r = x1 * y2 % p
    s = x2 * y1 % p
    w = (r + s) % p
    r = x1 * x2 % p
    s = y1 * y2 % p
    u = (s - a * r) % p
    r = z1 * z2 % p
    s = t1 * t2 % p
    v = (r * d_under - d_over * s) % p
    x3 = w * v % p
    t3 = u * w % p
    w = (r * d_under + d_over * s) % p
    y3 = u * w % p
    z3 = v * w % p
    x3 = x3 * d_under % p
    y3 = y3 * d_under % p
    t3 = t3 * d_under * d_under % p
    return (x3, y3, t3, z3)

def point_dbl_ref(x1, y1, t1, z1):
    xx = x1 * x1 % p
    yy = y1 * y1 % p
    zz = z1 * z1 % p
    xy = x1 * y1 % p
    t = 2 * xy % p
    u = (yy + a * xx) % p
    v = (yy - a * xx) % p
    w = (2 * zz - yy - a * xx) % p
    x3 = t * w % p
    y3 = u * v % p
    t3 = t * v % p
    z3 = u * w % p
    return (x3, y3, t3, z3)

def point_dbl_asm(x1, y1, t1, z1):
    r = x1 * x1 * a % p
    s = y1 * y1 % p
    u = (s + r) % p
    v = (s - r) % p
    y3 = u * v % p
    s = x1 * y1 * 2 % p
    t3 = s * v % p
    r = z1 * z1 * 2 % p
    w = (r - u) % p
    x3 = s * w % p
    z3 = u * w % p
    return (x3, y3, t3, z3)

def point_dbl_rfc(x1, y1, t1, z1):
    A = x1 * x1 % p
    B = y1 * y1 % p
    C = 2 * z1 * z1 % p
    H = A + B
    E = H - pow(x1 + y1, 2, p)
    G = A - B
    F = C + G
    x3 = E * F % p
    y3 = G * H % p
    t3 = E * H % p
    z3 = F * G
    return (x3, y3, t3, z3)

from functools import reduce

def xytz_cmp(P,Q):
    vec = (P[i] * Q[3] % p != P[3] * Q[i] % p for i in range(3))
    return reduce(lambda a, b: a or b, vec)

if __name__ == "__main__":
    fails = 0
    slen = 12
    for i in range(100):
        P = (os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)))
        Q = (os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)),
             os2int(secrets.token_bytes(slen)))
        R1 = point_add_rfc(*P, *Q)
        R2 = point_add_ref(*P, *Q)
        R3 = point_dbl_rfc(*P)
        R4 = point_dbl_asm(*P)
        if xytz_cmp(R1, R2): fails += 1
        if xytz_cmp(R3, R4): fails += 1
    print("{} test(s) failed.".format(fails))
