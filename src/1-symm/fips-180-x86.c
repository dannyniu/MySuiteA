/* DannyNiu/NJF, 2022-09-10. Public Domain. */

#include "fips-180.h"
#include <x86intrin.h>

#ifdef TEST_WITH_MOCK

#define Ch(x,y,z) ((x&y)^((~x)&z))
#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define Parity(x,y,z) (x^y^z)

__m128i x86_sha1rnds4(__m128i src1, __m128i src2, int t)
{
    uint32_t a[5], b[5], c[5], d[5], e[5], w[4];
    int j;

    _mm_storeu_si128((void *)w, src1);
    a[0] = w[3];
    b[0] = w[2];
    c[0] = w[1];
    d[0] = w[0];
    
    _mm_storeu_si128((void *)w, src2);
    w[0] ^= w[3];
    w[3] ^= w[0];
    w[0] ^= w[3];
    w[1] ^= w[2];
    w[2] ^= w[1];
    w[1] ^= w[2];

    j=0;

    a[j+1] =
        (t==0 ?  Ch(b[j],c[j],d[j]) : t==1 ? Parity(b[j],c[j],d[j]) :
         t==2 ? Maj(b[j],c[j],d[j]) : t==3 ? Parity(b[j],c[j],d[j]) : 0) +
        ((a[j] << 5) | (a[j] >> 27)) + w[j] +
        (t==0 ? 0x5a827999 : t==1 ? 0x6ed9eba1 :
         t==2 ? 0x8f1bbcdc : t==3 ? 0xca62c1d6 : 0);
    b[j+1] = a[j];
    c[j+1] = (b[j] << 30) | (b[j] >> 2);
    d[j+1] = c[j];
    e[j+1] = d[j];

    for(j=1; j<=3; j++)
    {
        a[j+1] =
            (t==0 ?  Ch(b[j],c[j],d[j]) : t==1 ? Parity(b[j],c[j],d[j]) :
             t==2 ? Maj(b[j],c[j],d[j]) : t==3 ? Parity(b[j],c[j],d[j]) : 0) +
            ((a[j] << 5) | (a[j] >> 27)) + w[j] + e[j] +
            (t==0 ? 0x5a827999 : t==1 ? 0x6ed9eba1 :
             t==2 ? 0x8f1bbcdc : t==3 ? 0xca62c1d6 : 0);
        b[j+1] = a[j];
        c[j+1] = (b[j] << 30) | (b[j] >> 2);
        d[j+1] = c[j];
        e[j+1] = d[j];
    }

    return _mm_set_epi32(a[4], b[4], c[4], d[4]);
}

__m128i x86_sha1nexte(__m128i src1, __m128i src2)
{
    uint32_t s[4];
    _mm_storeu_si128((void *)s, src1);
    s[3] = (s[3] << 30) | (s[3] >> 2);
    s[2] = s[1] = s[0] = 0;

    return _mm_add_epi32(src2, _mm_loadu_si128((void const *)s));
}

__m128i x86_sha1msg1(__m128i src1, __m128i src2)
{
    uint32_t u[4], v[4];
    _mm_storeu_si128((void *)u, src1);
    _mm_storeu_si128((void *)v, src2);
    u[3] ^= u[1];
    u[2] ^= u[0];
    u[1] ^= v[3];
    u[0] ^= v[2];
    return _mm_loadu_si128((void const *)u);
}

__m128i x86_sha1msg2(__m128i src1, __m128i src2)
{
    uint32_t u[4], v[4], w[4];
    _mm_storeu_si128((void *)u, src1);
    _mm_storeu_si128((void *)v, src2);
    w[3] = u[3] ^ v[2]; w[3] = (w[3] << 1) | (w[3] >> 31);
    w[2] = u[2] ^ v[1]; w[2] = (w[2] << 1) | (w[2] >> 31);
    w[1] = u[1] ^ v[0]; w[1] = (w[1] << 1) | (w[1] >> 31);
    w[0] = u[0] ^ w[3]; w[0] = (w[0] << 1) | (w[0] >> 31);
    return _mm_loadu_si128((void const *)w);
}

#define ROTL(x,n) (( (x)<<(n) )|( (x)>>(32-(n)) ))
#define ROTR(x,n) (( (x)>>(n) )|( (x)<<(32-(n)) ))

#define Sigma0(x) ( ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) )
#define Sigma1(x) ( ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) )
#define sigma0(x) ( ROTR(x,7) ^ ROTR(x,18) ^ (x>>3) )
#define sigma1(x) ( ROTR(x,17) ^ ROTR(x,19) ^ (x>>10) )

__m128i x86_sha256rnds2(__m128i src1, __m128i src2, __m128i msg)
{
    int i;
    uint32_t w[4];
    uint32_t a[3], b[3], c[3], d[3], e[3], f[3], g[3], h[3], k[2];

    _mm_storeu_si128((void *)w, src1);
    c[0] = w[3], d[0] = w[2], g[0] = w[1], h[0] = w[0];
    
    _mm_storeu_si128((void *)w, src2);
    a[0] = w[3], b[0] = w[2], e[0] = w[1], f[0] = w[0];

    _mm_storeu_si128((void *)w, msg);
    k[0] = w[0], k[1] = w[1];

    for(i=0; i<=1; i++)
    {
        a[i+1] =
            Ch(e[i],f[i],g[i]) +
            Maj(a[i],b[i],c[i]) + 
            Sigma1(e[i]) + k[i] + h[i] +
            Sigma0(a[i]);
        b[i+1] = a[i];
        c[i+1] = b[i];
        d[i+1] = c[i];
        e[i+1] =
            Ch(e[i],f[i],g[i]) +
            Sigma1(e[i]) + k[i] + h[i] + d[i];
        f[i+1] = e[i];
        g[i+1] = f[i];
        h[i+1] = g[i];
    }

    return _mm_set_epi32(a[2], b[2], e[2], f[2]);
}

__m128i x86_sha256msg1(__m128i src1, __m128i src2)
{
    uint32_t w[4], vv[4];
    _mm_storeu_si128((void *)w, src1);
    _mm_storeu_si128((void *)vv, src2);

    w[0] += sigma0(w[1]);
    w[1] += sigma0(w[2]);
    w[2] += sigma0(w[3]);
    w[3] += sigma0(vv[0]);

    return _mm_loadu_si128((void const *)w);
}

__m128i x86_sha256msg2(__m128i src1, __m128i src2)
{
    uint32_t w[4], vv[4];
    _mm_storeu_si128((void *)w, src1);
    _mm_storeu_si128((void *)vv, src2);

    w[0] += sigma1(vv[2]);
    w[1] += sigma1(vv[3]);
    w[2] += sigma1(w[0]);
    w[3] += sigma1(w[1]);
    
    return _mm_loadu_si128((void const *)w);
}

#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1

#else
#define x86_sha1rnds4(...) _mm_sha1rnds4_epu32(__VA_ARGS__)
#define x86_sha1nexte(...) _mm_sha1nexte_epu32(__VA_ARGS__)
#define x86_sha1msg1(...) _mm_sha1msg1_epu32(__VA_ARGS__)
#define x86_sha1msg2(...) _mm_sha1msg2_epu32(__VA_ARGS__)
#define x86_sha256rnds2(...) _mm_sha256rnds2_epu32(__VA_ARGS__)
#define x86_sha256msg1(...) _mm_sha256msg1_epu32(__VA_ARGS__)
#define x86_sha256msg2(...) _mm_sha256msg2_epu32(__VA_ARGS__)
#endif /* TEST_WITH_MOCK */

// Can't test this on QEMU-User (2022-09-10).
void compressfunc_sha1_ni(uint32_t H[5], uint32_t const *restrict M)
{
    __m128i w[4];
    __m128i abcd, e, save;
    uint32_t buf[4];
    int i;

    for(i=0; i<4; i++)
    {
        w[i] = _mm_loadu_si128((void const *)&M[i*4]);
        w[i] = _mm_shuffle_epi8(
            w[i], _mm_set_epi8(
                0, 1, 2, 3, 4, 5, 6, 7, 8,
                9, 10, 11, 12, 13, 14, 15));
    }

    abcd = _mm_set_epi32(H[0], H[1], H[2], H[3]);
    e    = _mm_set_epi32(H[4], 0, 0, 0);

    save = _mm_add_epi32(e, w[0]);
    
    for(i=0; i<20; i++)
    {
        e = abcd;
        
        if( 0 <= i && i < 5 ) abcd = x86_sha1rnds4(abcd, save, 0);
        if( 5 <= i && i < 10 ) abcd = x86_sha1rnds4(abcd, save, 1);
        if( 10 <= i && i < 15 ) abcd = x86_sha1rnds4(abcd, save, 2);
        if( 15 <= i && i < 20 ) abcd = x86_sha1rnds4(abcd, save, 3);

        if( i >= 1 ) w[(i-1)%4] = x86_sha1msg1(w[(i-1)%4], w[i%4]);
        if( i >= 2 ) w[(i-2)%4] ^= w[i%4];
        if( i >= 3 ) w[(i-3)%4] = x86_sha1msg2(w[(i-3)%4], w[i%4]);
        
        save = x86_sha1nexte(e, w[(i+1)%4]);
    }

    _mm_storeu_si128((void *)buf, abcd);
    for(i=0; i<4; i++) H[i] += buf[3-i];
    
    _mm_storeu_si128((void *)buf, e);
    H[4] += (buf[3] << 30) | (buf[3] >> 2);
}

static const uint32_t K_sha256[];

void compressfunc_sha256_ni(uint32_t H[8], uint32_t const *restrict M)
{
    __m128i w[4];
    __m128i abef, cdgh, save;
    uint32_t buf[4];
    int i;
    
    for(i=0; i<4; i++)
    {
        w[i] = _mm_loadu_si128((void const *)&M[i*4]);
        w[i] = _mm_shuffle_epi8(
            w[i], _mm_set_epi8(
                12, 13, 14, 15, 8, 9, 10, 11,
                4, 5, 6, 7, 0, 1, 2, 3));
    }

    abef = _mm_set_epi32(H[0], H[1], H[4], H[5]);
    cdgh = _mm_set_epi32(H[2], H[3], H[6], H[7]);

    for(i=0; i<16; i++)
    {
        save = _mm_add_epi32(
            w[i%4], _mm_loadu_si128((void const *)&K_sha256[i*4]));
        cdgh = x86_sha256rnds2(cdgh, abef, save);
        save = _mm_shuffle_epi32(save, 0x0e);
        abef = x86_sha256rnds2(abef, cdgh, save);

        if( i >= 3 )
        {
            save = w[i%4];
            save = _mm_alignr_epi8(save, w[(i-1)%4], 4);
            w[(i-3)%4] = _mm_add_epi32(w[(i-3)%4], save);
            w[(i-3)%4] = x86_sha256msg2(w[(i-3)%4], w[i%4]);
        }

        if( i >= 1 )
            w[(i-1)%4] = x86_sha256msg1(w[(i-1)%4], w[i%4]);
    }

    _mm_storeu_si128((void *)buf, abef);
    H[0] += buf[3];
    H[1] += buf[2];
    H[4] += buf[1];
    H[5] += buf[0];

    _mm_storeu_si128((void *)buf, cdgh);
    H[2] += buf[3];
    H[3] += buf[2];
    H[6] += buf[1];
    H[7] += buf[0];
}

void compressfunc_sha512_ni(uint64_t H[8], uint64_t const *restrict M)
{
    // x86 doesn't have native intrinsics for SHA-512 and its variants.
    compressfunc_sha512_ci(H, M);
}

#define IntrinSelf
#include "fips-180.c"
