/* DannyNiu/NJF, 2018-12-22. Public Domain. */

#ifndef MySuiteA_blake2_h
#define MySuiteA_blake2_h 1

// References: src/notes: "BLAKE2". 

#include "../mysuitea-common.h"

typedef struct blake2b_context {
    uint8_t     b[128];
    uint64_t    h[8];
    uint64_t    t;
    uint16_t    filled;
    uint8_t     outlen;
    uint8_t     pad[128 - (8*8 + 8 + 3)]; // align struct end. 
} blake2b_t, blake2b160_t, blake2b256_t, blake2b384_t, blake2b512_t;

typedef struct blake2s_context {
    uint8_t     b[64];
    uint32_t    h[8];
    uint64_t    t;
    uint16_t    filled;
    uint8_t     outlen;
    uint8_t     pad[64 - (4*8 + 8 + 3)]; // align struct end. 
} blake2s_t, blake2s128_t, blake2s160_t, blake2s224_t, blake2s256_t;

void BLAKE2b160_Init(blake2b_t *restrict x);
void BLAKE2b256_Init(blake2b_t *restrict x);
void BLAKE2b384_Init(blake2b_t *restrict x);
void BLAKE2b512_Init(blake2b_t *restrict x);

void BLAKE2s128_Init(blake2s_t *restrict x);
void BLAKE2s160_Init(blake2s_t *restrict x);
void BLAKE2s224_Init(blake2s_t *restrict x);
void BLAKE2s256_Init(blake2s_t *restrict x);

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

void blake2b_final(blake2b_t *restrict x, void *restrict out);
#define BLAKE2b160_Final blake2b_final
#define BLAKE2b256_Final blake2b_final
#define BLAKE2b384_Final blake2b_final
#define BLAKE2b512_Final blake2b_final

void blake2s_final(blake2s_t *restrict x, void *restrict out);
#define BLAKE2s128_Final blake2s_final
#define BLAKE2s160_Final blake2s_final
#define BLAKE2s224_Final blake2s_final
#define BLAKE2s256_Final blake2s_final

#define cBLAKE2b(bits,q) (                                      \
        q==outBytes ? bits/8 :                                  \
        q==blockBytes ? 128 :                                   \
        q==contextBytes ? sizeof(struct blake2b_context) :      \
        q==InitFunc   ? (uintptr_t)BLAKE2b##bits##_Init :       \
        q==UpdateFunc ? (uintptr_t)BLAKE2b##bits##_Update :     \
        q==FinalFunc  ? (uintptr_t)BLAKE2b##bits##_Final :      \
        0)

#define cBLAKE2s(bits,q) (                                      \
        q==outBytes ? bits/8 :                                  \
        q==blockBytes ? 64 :                                    \
        q==contextBytes ? sizeof(struct blake2s_context) :      \
        q==InitFunc   ? (uintptr_t)BLAKE2s##bits##_Init :       \
        q==UpdateFunc ? (uintptr_t)BLAKE2s##bits##_Update :     \
        q==FinalFunc  ? (uintptr_t)BLAKE2s##bits##_Final :      \
        0)

#define cBLAKE2b160(q) cBLAKE2b(160,q)
#define cBLAKE2b256(q) cBLAKE2b(256,q)
#define cBLAKE2b384(q) cBLAKE2b(384,q)
#define cBLAKE2b512(q) cBLAKE2b(512,q)

#define cBLAKE2s128(q) cBLAKE2s(128,q)
#define cBLAKE2s160(q) cBLAKE2s(160,q)
#define cBLAKE2s224(q) cBLAKE2s(224,q)
#define cBLAKE2s256(q) cBLAKE2s(256,q)

uintptr_t iBLAKE2b160(int q);
uintptr_t iBLAKE2b256(int q);
uintptr_t iBLAKE2b384(int q);
uintptr_t iBLAKE2b512(int q);

uintptr_t iBLAKE2s128(int q);
uintptr_t iBLAKE2s160(int q);
uintptr_t iBLAKE2s224(int q);
uintptr_t iBLAKE2s256(int q);

#endif /* MySuiteA_blake2_h */