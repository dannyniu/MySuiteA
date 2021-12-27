#!/usr/bin/env python3

global p, a
p = 65537
a = 2

def point_add_asm(x1, y1, z1, x2, y2, z2):
    u = y2 * z1 %p
    t = y1 * z2 %p
    u = (u - t) %p
    v = x2 * z1 %p
    t = x1 * z2 %p
    v = (v - t) %p
    # x
    t = u * u %p
    x = t * z1 %p
    t = v * v %p
    s = t * x1 %p
    s = s * 2 %p
    x = (x - s) %p
    t = x * z2 %p
    s = v * v %p
    x = s * v %p
    t = (t - x) %p
    x = t * v %p
    # y
    t = v * v %p
    s = t * u %p
    y = s * x1 %p
    y = y * 3 %p
    s = t * v %p
    v = s
    t = v * y1 %p
    y = (y - t) %p
    t = u * u %p
    s = t * u %p
    t = s * z1 %p
    y = (y - t) %p
    t = y * z2 %p
    y = u * v %p
    y = (t + y) %p
    # z
    t = v * z1 %p
    z = t * z2 %p
    return (x,y,z)

def point_add_ref(x1, y1, z1, x2, y2, z2):
    u = (y2 * z1 - y1 * z2) %p
    v = (x2 * z1 - x1 * z2) %p
    x = v * (z2 * (z1 * u * u - 2 * x1 * v * v) - v * v * v)
    x = x % p
    y = z2 * (3 * x1 * u * v ** 2 - y1 * v ** 3 - z1 * u ** 3) + u * v ** 3
    y = y % p
    z = v ** 3 * z1 * z2 % p
    return (x,y,z)

def point_dbl_asm(x1, y1, z1):
    w = x1 * x1 %p
    w = w * 3 %p
    t = z1 * z1 %p
    s = t * a %p
    w = (w + s) %p
    # y
    y = w * x1 %p
    y = y * 3 %p
    t = y1 * y1 %p
    s = t * z1 %p
    s = s * 2 %p
    y = (y - s) %p
    s = y * t %p
    y = s * z1 %p
    y = y * 4 %p
    # x
    s = t * z1 %p
    x = s * x1 %p
    x = x * 8 %p
    s = w * w %p
    x = (s - x) %p
    # - w ** 3
    t = s * w %p
    y = (y - t) %p
    # x
    t = y1 * z1 %p
    s = x * 2 %p
    x = t * s %p
    # z
    s = t * t %p
    z = s * t %p
    z = z * 8 %p
    return (x,y,z)

def point_dbl_ref(x1, y1, z1):
    w = (3 * x1 ** 2 + a * z1 ** 2) % p
    x = 2 * y1 * z1 * (w ** 2 - 8 * x1 * y1 ** 2 * z1) %p
    y = 4 * y1 ** 2 * z1 * (3 * w * x1 - 2 * y1 ** 2 * z1) - w ** 3
    y = y % p
    z = 8 * (y1 * z1) ** 3 %p
    return (x,y,z)

def set_p(new_p):
    global p
    p = new_p

def set_a(new_a):
    global a
    a = new_a

if __name__ == "__main__":
    print(repr(point_add_asm(1, 2, 3000, 4, 5000, 6)))
    print(repr(point_add_ref(1, 2, 3000, 4, 5000, 6)))
    
    print(repr(point_dbl_asm(3000, 5, 5000)))
    print(repr(point_dbl_ref(3000, 5, 5000)))
