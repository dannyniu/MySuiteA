/* DannyNiu/NJF, 2018-01-30. Public Domain. */

#ifndef MySuiteA_umath_h
#define MySuiteA_umath_h 1

#include <stdint.h>

#if !(__STDC_VERSION__ >= 199901L)
#error This object require C99 or later to compile successfully.
#endif

int16_t __umod16(int16_t a, int16_t b);
int32_t __umod32(int32_t a, int32_t b);
int64_t __umod64(int64_t a, int64_t b);
#define umod(a,b)                               \
    _Generic((a)+(b),                           \
             int16_t: __umod16((a),(b)),        \
             int32_t: __umod32((a),(b)),        \
             int64_t: __umod64((a),(b))         \
        )

int16_t __imod16(int16_t a, int16_t b);
int32_t __imod32(int32_t a, int32_t b);
int64_t __imod64(int64_t a, int64_t b);
#define imod(a,b)                               \
    _Generic((a)+(b),                           \
             int16_t: __imod16((a),(b)),        \
             int32_t: __imod32((a),(b)),        \
             int64_t: __imod64((a),(b))         \
        )

int16_t __egcd16(int16_t a, int16_t p);
int32_t __egcd32(int32_t a, int32_t p);
int64_t __egcd64(int64_t a, int64_t p);
#define egcd(a,p)                               \
    _Generic((a)+(p),                           \
             int16_t: __egcd16((a),(p)),        \
             int32_t: __egcd32((a),(p)),        \
             int64_t: __egcd64((a),(p))         \
        )

#endif /* MySuiteA_umath_h */
