/* DannyNiu/NJF, 2018-12-22. Public Domain. */

#ifndef MySuiteA_blake2_h
#define MySuiteA_blake2_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         8 *27       .
typedef struct blake2b_context {
    uint8_t     b[128];
    uint64_t    h[8];
    uint64_t    t;
    uint32_t    filled;
    uint32_t    outlen;
    uint32_t    keylen;
    int32_t     finalized;
} blake2b_t, blake2b160_t, blake2b256_t, blake2b384_t, blake2b512_t;

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         8 *15       .
typedef struct blake2s_context {
    uint8_t     b[64];
    uint32_t    h[8];
    uint64_t    t;
    uint32_t    filled;
    uint32_t    outlen;
    uint32_t    keylen;
    int32_t     finalized;
} blake2s_t, blake2s128_t, blake2s160_t, blake2s224_t, blake2s256_t;

void BLAKE2b160_Init(blake2b_t *restrict x);
void BLAKE2b256_Init(blake2b_t *restrict x);
void BLAKE2b384_Init(blake2b_t *restrict x);
void BLAKE2b512_Init(blake2b_t *restrict x);

void BLAKE2s128_Init(blake2s_t *restrict x);
void BLAKE2s160_Init(blake2s_t *restrict x);
void BLAKE2s224_Init(blake2s_t *restrict x);
void BLAKE2s256_Init(blake2s_t *restrict x);

#define BLAKE2b_KPARAMS                                         \
    blake2b_t *restrict x, void const *restrict k, size_t klen

#define BLAKE2s_KPARAMS                                         \
    blake2s_t *restrict x, void const *restrict k, size_t klen

void *kBLAKE2b160_Init(BLAKE2b_KPARAMS);
void *kBLAKE2b256_Init(BLAKE2b_KPARAMS);
void *kBLAKE2b384_Init(BLAKE2b_KPARAMS);
void *kBLAKE2b512_Init(BLAKE2b_KPARAMS);

void *kBLAKE2s128_Init(BLAKE2s_KPARAMS);
void *kBLAKE2s160_Init(BLAKE2s_KPARAMS);
void *kBLAKE2s224_Init(BLAKE2s_KPARAMS);
void *kBLAKE2s256_Init(BLAKE2s_KPARAMS);

void blake2b_update(
    blake2b_t *restrict x,
    void const *restrict data,
    size_t len);
#define BLAKE2b160_Update blake2b_update
#define BLAKE2b256_Update blake2b_update
#define BLAKE2b384_Update blake2b_update
#define BLAKE2b512_Update blake2b_update

void blake2s_update(
    blake2s_t *restrict x,
    void const *restrict data,
    size_t len);
#define BLAKE2s128_Update blake2s_update
#define BLAKE2s160_Update blake2s_update
#define BLAKE2s224_Update blake2s_update
#define BLAKE2s256_Update blake2s_update

void blake2b_final(blake2b_t *restrict x, void *restrict out, size_t t);
#define BLAKE2b160_Final blake2b_final
#define BLAKE2b256_Final blake2b_final
#define BLAKE2b384_Final blake2b_final
#define BLAKE2b512_Final blake2b_final

void blake2s_final(blake2s_t *restrict x, void *restrict out, size_t t);
#define BLAKE2s128_Final blake2s_final
#define BLAKE2s160_Final blake2s_final
#define BLAKE2s224_Final blake2s_final
#define BLAKE2s256_Final blake2s_final

#define cBLAKE2b(bits,q) (                                              \
        q==outBytes ? bits/8 :                                          \
        q==blockBytes ? 128 :                                           \
        q==contextBytes ? (IntPtr)sizeof(struct blake2b_context) :      \
        0)

#define xBLAKE2b(bits,q) (                                      \
        q==InitFunc   ? (IntPtr)BLAKE2b##bits##_Init :          \
        q==UpdateFunc ? (IntPtr)BLAKE2b##bits##_Update :        \
        q==FinalFunc  ? (IntPtr)BLAKE2b##bits##_Final :         \
        cBLAKE2b(bits,q) )

#define cBLAKE2s(bits,q) (                                              \
        q==outBytes ? bits/8 :                                          \
        q==blockBytes ? 64 :                                            \
        q==contextBytes ? (IntPtr)sizeof(struct blake2s_context) :      \
        0)

#define xBLAKE2s(bits,q) (                                      \
        q==InitFunc   ? (IntPtr)BLAKE2s##bits##_Init :          \
        q==UpdateFunc ? (IntPtr)BLAKE2s##bits##_Update :        \
        q==FinalFunc  ? (IntPtr)BLAKE2s##bits##_Final :         \
        cBLAKE2s(bits,q) )

#define cBLAKE2b160(q) cBLAKE2b(160,q)
#define cBLAKE2b256(q) cBLAKE2b(256,q)
#define cBLAKE2b384(q) cBLAKE2b(384,q)
#define cBLAKE2b512(q) cBLAKE2b(512,q)

#define xBLAKE2b160(q) xBLAKE2b(160,q)
#define xBLAKE2b256(q) xBLAKE2b(256,q)
#define xBLAKE2b384(q) xBLAKE2b(384,q)
#define xBLAKE2b512(q) xBLAKE2b(512,q)

#define cBLAKE2s128(q) cBLAKE2s(128,q)
#define cBLAKE2s160(q) cBLAKE2s(160,q)
#define cBLAKE2s224(q) cBLAKE2s(224,q)
#define cBLAKE2s256(q) cBLAKE2s(256,q)

#define xBLAKE2s128(q) xBLAKE2s(128,q)
#define xBLAKE2s160(q) xBLAKE2s(160,q)
#define xBLAKE2s224(q) xBLAKE2s(224,q)
#define xBLAKE2s256(q) xBLAKE2s(256,q)

// 2020-09-19:
// Haven't found motivation to override the unkeyed ``InitFunc'' yet.

#define ckBLAKE2b(bits,q) (                             \
        q==keyBytes ? -64 :                             \
        cBLAKE2b(bits,q))

#define xkBLAKE2b(bits,q) (                             \
        q==keyBytes ? -64 :                             \
        q==KInitFunc ? (IntPtr)kBLAKE2b##bits##_Init :  \
        xBLAKE2b(bits,q))

#define ckBLAKE2s(bits,q) (                             \
        q==keyBytes ? -32 :                             \
        cBLAKE2s(bits,q))

#define xkBLAKE2s(bits,q) (                             \
        q==keyBytes ? -32 :                             \
        q==KInitFunc ? (IntPtr)kBLAKE2s##bits##_Init :  \
        xBLAKE2s(bits,q))

#define ckBLAKE2b160(q) ckBLAKE2b(160,q)
#define ckBLAKE2b256(q) ckBLAKE2b(256,q)
#define ckBLAKE2b384(q) ckBLAKE2b(384,q)
#define ckBLAKE2b512(q) ckBLAKE2b(512,q)

#define xkBLAKE2b160(q) xkBLAKE2b(160,q)
#define xkBLAKE2b256(q) xkBLAKE2b(256,q)
#define xkBLAKE2b384(q) xkBLAKE2b(384,q)
#define xkBLAKE2b512(q) xkBLAKE2b(512,q)

#define ckBLAKE2s128(q) ckBLAKE2s(128,q)
#define ckBLAKE2s160(q) ckBLAKE2s(160,q)
#define ckBLAKE2s224(q) ckBLAKE2s(224,q)
#define ckBLAKE2s256(q) ckBLAKE2s(256,q)

#define xkBLAKE2s128(q) xkBLAKE2s(128,q)
#define xkBLAKE2s160(q) xkBLAKE2s(160,q)
#define xkBLAKE2s224(q) xkBLAKE2s(224,q)
#define xkBLAKE2s256(q) xkBLAKE2s(256,q)

IntPtr iBLAKE2b160(int q);
IntPtr iBLAKE2b256(int q);
IntPtr iBLAKE2b384(int q);
IntPtr iBLAKE2b512(int q);

IntPtr iBLAKE2s128(int q);
IntPtr iBLAKE2s160(int q);
IntPtr iBLAKE2s224(int q);
IntPtr iBLAKE2s256(int q);

IntPtr ikBLAKE2b160(int q);
IntPtr ikBLAKE2b256(int q);
IntPtr ikBLAKE2b384(int q);
IntPtr ikBLAKE2b512(int q);

IntPtr ikBLAKE2s128(int q);
IntPtr ikBLAKE2s160(int q);
IntPtr ikBLAKE2s224(int q);
IntPtr ikBLAKE2s256(int q);

#endif /* MySuiteA_blake2_h */
