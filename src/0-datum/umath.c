/* DannyNiu/NJF, 2018-01-30. Public Domain. */

#include "umath.h"

// Things to bare in mind here:
//
// Quoted from the public draft N1570 of ISO/IEC 9899:2011
// which said the following about the C programming language:
//
// " When integers are divided, the result of the / operator
//  is the algebraic quotient with any fractional part discarded. ^105)
//  If the quotient a/b is representable, the expression
//  (a/b)*b + a%b shall equal a; otherwise, the behavior of both
//  a/b and a%b is undefined. "
//
// 105) This is often called "truncation toward zero". 

#define define_umod(name,type)          \
    type name(type a, type b) {         \
        type r = a % b;                 \
        return r<0 ? r+b : r;           \
    }

define_umod(__umod16, int16_t)
define_umod(__umod32, int32_t)
define_umod(__umod64, int64_t)

#define define_imod(name,type)          \
    type name(type a, type b) {         \
        type r = a % b;                 \
        return                          \
            r<(-b)/2 ? r+b :            \
            r>(b-1)/2 ? r-b : r;        \
    }

define_imod(__imod16, int16_t)
define_imod(__imod32, int32_t)
define_imod(__imod64, int64_t)

#define define_egcd(name,type)                  \
    type name(type a, type p) {                 \
        if( !p ) return a;                      \
                                                \
        type                                    \
            i = p,                              \
            j = umod(a, p),                     \
            y2 = 0, y1 = 1,                     \
            q, r, y;                            \
                                                \
        while( j > 0 ) {                        \
            q = i/j;                            \
            r = i-j*q;                          \
            y = y2-y1*q;                        \
                                                \
            i=j, j=r;                           \
            y2=y1, y1=y;                        \
        }                                       \
                                                \
        if( i != 1 ) return 0;                  \
        else return y2<0 ? y2+p : y2;           \
    }

define_egcd(__egcd16, int16_t)
define_egcd(__egcd32, int32_t)
define_egcd(__egcd64, int64_t)
