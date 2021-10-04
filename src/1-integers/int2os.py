#!/usr/bin/env python3

def int2os(x, l):
    ret = b''
    while l > 0:
        ret = bytes([x % 256]) + ret
        x >>= 8
        l -= 1
    return ret

def os2int(v):
    ret = 0
    for b in v: ret = (ret << 8) | b
    return ret
