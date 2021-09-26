/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_sha_h
#define MySuiteA_sha_h 1

#include "../mysuitea-common.h"

// sizeof(uint32_t) * (26 = 6.5 * 4) on ILP32 and I32LP64.
typedef struct sha1_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint32_t    H[5];
    uint32_t    pad_H6; // to silence a warning. 
    union {
        uint32_t    Msg32[16];
        uint8_t     Msg8[64];
    };
} sha1_t; // only included for completeness, deprecated. 

void SHA1_Init(sha1_t *restrict sha);
void SHA1_Update(sha1_t *restrict sha, void const *restrict data, size_t len);
void SHA1_Final(sha1_t *restrict sha, void *restrict out, size_t t);

// sizeof(uint32_t) * (28 = 7 * 4) on ILP32 and I32LP64.
typedef struct sha256_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len;
    uint32_t    H[8];
    union {
        uint32_t    Msg32[16];
        uint8_t     Msg8[64];
    };
} sha224_t, sha256_t;

void sha256_update(sha256_t *restrict sha, void const *restrict data, size_t len);
#define SHA224_Update sha256_update
#define SHA256_Update sha256_update
void SHA224_Init(sha224_t *restrict sha);
void SHA256_Init(sha256_t *restrict sha);
void SHA224_Final(sha224_t *restrict sha, void *restrict out, size_t t);
void SHA256_Final(sha256_t *restrict sha, void *restrict out, size_t t);

// sizeof(uint32_t) * (52 = 13 * 4) on ILP32 and I32LP64.
typedef struct sha512_context {
    int         finalized;
    unsigned    filled;
    uint64_t    len; // [!A-E-D!]: msglen > 2^64 are unsupported.
    uint64_t    H[8];
    union {
        uint64_t    Msg64[16];
        uint8_t     Msg8[128];
    };
} sha384_t, sha512_t, sha512t_t;

void sha512_update(sha512_t *restrict sha, void const *restrict data, size_t len);
#define SHA384_Update sha512_update
#define SHA512_Update sha512_update
void SHA384_Init(sha384_t *restrict sha);
void SHA512_Init(sha512_t *restrict sha);
void SHA384_Final(sha384_t *restrict sha, void *restrict out, size_t t);
void SHA512_Final(sha512_t *restrict sha, void *restrict out, size_t t);
#define SHA512t224_Update sha512_update
#define SHA512t256_Update sha512_update
void SHA512t224_Init(sha512t_t *restrict sha);
void SHA512t256_Init(sha512t_t *restrict sha);
void SHA512t224_Final(sha512t_t *restrict sha, void *restrict out, size_t t);
void SHA512t256_Final(sha512t_t *restrict sha, void *restrict out, size_t t);

#define cSHA1(q) (                              \
        q==outBytes ? 20 :                      \
        q==blockBytes ? 64 :                    \
        q==contextBytes ? sizeof(sha1_t) :      \
        0)

#define xSHA1(q) (                              \
        q==InitFunc   ? (IntPtr)SHA1_Init :     \
        q==UpdateFunc ? (IntPtr)SHA1_Update :   \
        q==FinalFunc  ? (IntPtr)SHA1_Final :    \
        cSHA1(q) )

#define cSHAoN(bits,blk,q) (                            \
        q==outBytes ? bits/8 :                          \
        q==blockBytes ? blk :                           \
        q==contextBytes ? sizeof(sha##bits##_t) :       \
        0)

#define xSHAoN(bits,blk,q) (                            \
        q==InitFunc   ? (IntPtr)SHA##bits##_Init :      \
        q==UpdateFunc ? (IntPtr)SHA##bits##_Update :    \
        q==FinalFunc  ? (IntPtr)SHA##bits##_Final :     \
        cSHAoN(bits,blk,q) )

#define cSHA512tN(bits,q) (                     \
        q==outBytes ? bits/8 :                  \
        q==blockBytes ? 128 :                   \
        q==contextBytes ? sizeof(sha512t_t) :   \
        0)

#define xSHA512tN(bits,q) (                                     \
        q==InitFunc   ? (IntPtr)SHA512t##bits##_Init :          \
        q==UpdateFunc ? (IntPtr)SHA512t##bits##_Update :        \
        q==FinalFunc  ? (IntPtr)SHA512t##bits##_Final :         \
        cSHA512tN(bits,q) )

#define cSHA224(q) cSHAoN(224,64,q)
#define cSHA256(q) cSHAoN(256,64,q)
#define cSHA384(q) cSHAoN(384,128,q)
#define cSHA512(q) cSHAoN(512,128,q)
#define cSHA512t224(q) cSHA512tN(224,q)
#define cSHA512t256(q) cSHA512tN(256,q)

#define xSHA224(q) xSHAoN(224,64,q)
#define xSHA256(q) xSHAoN(256,64,q)
#define xSHA384(q) xSHAoN(384,128,q)
#define xSHA512(q) xSHAoN(512,128,q)
#define xSHA512t224(q) xSHA512tN(224,q)
#define xSHA512t256(q) xSHA512tN(256,q)

IntPtr iSHA1(int q);
IntPtr iSHA224(int q);
IntPtr iSHA256(int q);
IntPtr iSHA384(int q);
IntPtr iSHA512(int q);
IntPtr iSHA512t224(int q);
IntPtr iSHA512t256(int q);

#endif
