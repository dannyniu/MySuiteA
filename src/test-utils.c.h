/* DannyNiu/NJF, 2020-09-20. Public Domain. */

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void *scanhex(uint8_t *restrict out, size_t len, char const *restrict in)
{
    int n;
    while( isxdigit((int)*in) && len-- &&
           sscanf(in, " %2"SCNx8" %n", out, &n) )
    {
        in += n;
        out++;
    }
    return out;
}

void dumphex(uint8_t const *data, size_t len)
{
    for(size_t i=0; i<len; i+=16)
    {
        for(size_t j=0; j<16; j++)
            if( i+j < len ) fprintf(stderr, "%02x ", data[i+j]);

        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

void *frealloc(void *old, size_t len)
{
    free(old);
    return malloc(len);
}

static uint64_t ws;
#define p 521UL

uint64_t u64permute(uint64_t x, uint32_t w)
{
    x ^= 0x8000000100000000 | w;
    x *= 0x13110d0b07050302;
    x = (x << 11) | (x >> 53);
    x += 0x89837f716d6b6765;
    return x;
}

unsigned long myrand(void)
{
    unsigned long ret = (uint32_t)(ws = u64permute(ws, 0));
    return ret % p;
}

void mysrand(unsigned long x) { ws = u64permute(ws, x); }
#undef p

#define u8cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 56 | u7cc((s)+1) : 0)
#define u7cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 48 | u6cc((s)+1) : 0)
#define u6cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 40 | u5cc((s)+1) : 0)
#define u5cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 32 | u4cc((s)+1) : 0)
#define u4cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 24 | u3cc((s)+1) : 0)
#define u3cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 16 | u2cc((s)+1) : 0)
#define u2cc(s) ( (s)[0] ? (uint64_t)(s)[0] <<  8 | (s)[1] : 0)
