/* DannyNiu/NJF, 2020-09-20. Public Domain. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static unsigned long a, b;
#define p 521UL

void mysrand(unsigned long x) { a = b = x % p; }
unsigned long myrand(void) {
    unsigned long x, y;
    x = a*a + p*p - b*b;
    x %= p;
    y = 2 * a * b;
    y %= p;
    a = x;
    b = y;
    return x;
}

#define u8cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 56 | u7cc((s)+1) : 0)
#define u7cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 48 | u6cc((s)+1) : 0)
#define u6cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 40 | u5cc((s)+1) : 0)
#define u5cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 32 | u4cc((s)+1) : 0)
#define u4cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 24 | u3cc((s)+1) : 0)
#define u3cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 16 | u2cc((s)+1) : 0)
#define u2cc(s) ( (s)[0] ? (uint64_t)(s)[0] <<  8 | (s)[1] : 0)
