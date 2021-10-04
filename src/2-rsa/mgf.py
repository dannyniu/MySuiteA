#!/usr/bin/env python3

import sys, hashlib

sys.path += ["../src/1-integers"]

from int2os import *

def MGF1(seed, hashname, masklen):
    hLen = hashlib.new(hashname).digest_size
    T = b''
    C = 0
    while len(T) < masklen:
        T += hashlib.new(
            hashname,
            data=seed+int2os(C, 4)).digest()
        C += 1
    return T[0:masklen]

def bytesXor(a, b):
    return bytes(map((lambda u, v: u ^ v), a, b))
