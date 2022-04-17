#!/usr/bin/env python3

global p, a
p = 65537
a = 2

def set_p(new_p):
    global p
    p = new_p

def set_a(new_a):
    global a
    a = new_a

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

def point_add_rcb15_ref(x1, y1, z1, x2, y2, z2, a, b):
    x1x2 = x1 * x2 % p
    x1y2 = x1 * y2 % p
    x1z2 = x1 * z2 % p
    x2y1 = y1 * x2 % p
    y1y2 = y1 * y2 % p
    y1z2 = y1 * z2 % p
    x2z1 = z1 * x2 % p
    y2z1 = z1 * y2 % p
    z1z2 = z1 * z2 % p
    x = (x1y2 + x2y1) * (y1y2 - a*(x1z2 + x2z1) - 3*b*z1z2)
    x -= (y1z2 + y2z1) * (a*x1x2 + 3*b*(x1z2 + x2z1) - a*a*z1z2)
    x %= p
    y = (3*x1x2 + a*z1z2) * (a*x1x2 + 3*b*(x1z2 + x2z1) - a*a*z1z2)
    y += (y1y2 + a*(x1z2 + x2z1) + 3*b*z1z2) * (y1y2 - a*(x1z2 + x2z1) - 3*b*z1z2)
    y %= p
    z = (y1z2 + y2z1) * (y1y2 + a*(x1z2 + x2z1) + 3*b*z1z2)
    z += (x1y2 + x2y1) * (3*x1x2 + a*z1z2)
    z %= p
    return (x,y,z)

def point_add_rcb15_original(X1, Y1, Z1, X2, Y2, Z2, a, b):
    b3 = b*3
    t0 = X1 * X2 ; t1 = Y1 * Y2 ; t2 = Z1 * Z2 ;
    t3 = X1 + Y1 ; t4 = X2 + Y2 ; t3 = t3 * t4 ;
    t4 = t0 + t1 ; t3 = t3 - t4 ; t4 = X1 + Z1 ;
    t5 = X2 + Z2 ; t4 = t4 * t5 ; t5 = t0 + t2 ;
    t4 = t4 - t5 ; t5 = Y1 + Z1 ; X3 = Y2 + Z2 ;
    t5 = t5 * X3 ; X3 = t1 + t2 ; t5 = t5 - X3 ;
    Z3 = a * t4 ; X3 = b3 * t2 ; Z3 = X3 + Z3 ;
    X3 = t1 - Z3 ; Z3 = t1 + Z3 ; Y3 = X3 * Z3 ;
    t1 = t0 + t0 ; t1 = t1 + t0 ; t2 = a * t2 ; # 25. 26. 27.
    t4 = b3 * t4 ; t1 = t1 + t2 ; t2 = t0 - t2 ;
    t2 = a * t2 ; t4 = t4 + t2 ; t0 = t1 * t4 ;
    Y3 = Y3 + t0 ; t0 = t5 * t4 ; X3 = t3 * X3 ;
    X3 = X3 - t0 ; t0 = t3 * t1 ; Z3 = t5 * Z3 ;
    Z3 = Z3 + t0 ;
    return (X3 , Y3 , Z3);

def point_add_rcb15_ref_asm(X1, Y1, Z1, X2, Y2, Z2, a, b):
    global p
    b3 = b*3
    t0 = (X1 * X2) %p ; t1 = (Y1 * Y2) %p ; t2 = (Z1 * Z2) %p ; # 1. 2. 3.
    t3 = (X1 + Y1) %p ; t4 = (X2 + Y2) %p ; t3 = (t3 * t4) %p ; # 4. 5. 6.
    t4 = (t0 + t1) %p ; t3 = (t3 - t4) %p ; t4 = (X1 + Z1) %p ; # 7. 8. 9.
    t5 = (X2 + Z2) %p ; t4 = (t4 * t5) %p ; t5 = (t0 + t2) %p ; # 10. 11. 12.
    t4 = (t4 - t5) %p ; t5 = (Y1 + Z1) %p ; X3 = (Y2 + Z2) %p ; # 13. 14. 15.
    t5 = (t5 * X3) %p ; X3 = (t1 + t2) %p ; t5 = (t5 - X3) %p ; # 16. 17. 18.
    Z3 = (a  * t4) %p ; X3 = (b3 * t2) %p ; Z3 = (X3 + Z3) %p ; # 19. 20. 21.
    X3 = (t1 - Z3) %p ; Z3 = (t1 + Z3) %p ; Y3 = (X3 * Z3) %p ; # 22. 23. 24.
    t1 = (t0 + t0) %p ; t1 = (t1 + t0) %p ; t2 = (a  * t2) %p ; # 25. 26. 27.
    t1 = (t1 + t2) %p ; t2 = (t0 - t2) %p ;
    t2 = (a  * t2) %p ;
    t4 = (b3 * t4) %p ; t4 = (t4 + t2) %p ;
    t0 = (t1 * t4) %p ; Y3 = (Y3 + t0) %p ;
    t0 = (t5 * t4) %p ; X3 = (t3 * X3) %p ; X3 = (X3 - t0) %p ;
    t0 = (t3 * t1) %p ; Z3 = (t5 * Z3) %p ; Z3 = (Z3 + t0) %p ;
    return (X3 , Y3 , Z3);

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

def point_scl(x1, y1, z1, d, a, b):
    accum = (0, 1, 0)
    tmp1 = (x1, y1, z1)
    i=0
    while d != 0:
        mask = d & 1
        if mask: accum = point_add_rcb15_ref(*accum, *tmp1, a, b)
        d = d >> 1
        i = i + 1
        tmp1 = point_dbl_ref(*tmp1)
    return accum

if __name__ == "__main__":
    print(repr(point_add_asm(1, 2, 3000, 4, 5000, 6)))
    print(repr(point_add_ref(1, 2, 3000, 4, 5000, 6)))
    print(repr(point_dbl_asm(3000, 5, 5000)))
    print(repr(point_dbl_ref(3000, 5, 5000)))
