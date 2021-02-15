/* DannyNiu/NJF, 2020-09-20. Public Domain. */

#include <ctype.h>
#include <inttypes.h>
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
            if( i+j < len ) printf("%02x ", data[i+j]);

        printf("\n");
    }
    printf("\n");
}

void *frealloc(void *old, size_t len)
{
    free(old);
    return malloc(len);
}

static uint32_t rnd[4], i;
#define p 521UL

#define qround(a, b, c, d)                      \
    {                                           \
        a += b; d ^= a; d = (d<<16)|(d>>16);    \
        c += d; b ^= c; b = (b<<12)|(b>>20);    \
        a += b; d ^= a; d = (d<< 8)|(d>>24);    \
        c += d; b ^= c; b = (b<< 7)|(b>>25);    \
    }

void mysrand_permute()
{
    for(int c=1; c<4; c++)
    {
        rnd[0] ^= 0x9e377900 | c;
        for(int r=0; r<c; r++) qround(rnd[0], rnd[1], rnd[2], rnd[3]);
    }
}

unsigned long myrand(void)
{
    unsigned long ret = rnd[i++] % p;
    if( i >= 4 ) { mysrand_permute(), i=0; }
    return ret;
}
    
void mysrand(unsigned long x) { rnd[0] = x; }
#undef p

#define u8cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 56 | u7cc((s)+1) : 0)
#define u7cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 48 | u6cc((s)+1) : 0)
#define u6cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 40 | u5cc((s)+1) : 0)
#define u5cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 32 | u4cc((s)+1) : 0)
#define u4cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 24 | u3cc((s)+1) : 0)
#define u3cc(s) ( (s)[0] ? (uint64_t)(s)[0] << 16 | u2cc((s)+1) : 0)
#define u2cc(s) ( (s)[0] ? (uint64_t)(s)[0] <<  8 | (s)[1] : 0)
