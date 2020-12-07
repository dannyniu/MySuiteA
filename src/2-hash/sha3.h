/* DannyNiu/NJF, 2018-02-05. Public Domain. */

#ifndef MySuiteA_sha3_h
#define MySuiteA_sha3_h 1

#include "../mysuitea-common.h"
#include "../1-symm/keccak.h"
#include "../1-symm/sponge.h"

typedef struct sha3_context {
    sponge_t    sponge;
    union {
        uint8_t     u8[200];
        uint64_t    u64[25]; // for alignment. 
    } state;
} sha3_t, sha3_224_t, sha3_256_t, sha3_384_t, sha3_512_t;

void SHA3_224_Init(sha3_t *restrict x);
void SHA3_256_Init(sha3_t *restrict x);
void SHA3_384_Init(sha3_t *restrict x);
void SHA3_512_Init(sha3_t *restrict x);

void SHA3_Update(sha3_t *restrict x, void const *restrict data, size_t len);
#define SHA3_224_Update SHA3_Update
#define SHA3_256_Update SHA3_Update
#define SHA3_384_Update SHA3_Update
#define SHA3_512_Update SHA3_Update

void SHA3_224_Final(sha3_t *restrict x, void *restrict out, size_t t);
void SHA3_256_Final(sha3_t *restrict x, void *restrict out, size_t t);
void SHA3_384_Final(sha3_t *restrict x, void *restrict out, size_t t);
void SHA3_512_Final(sha3_t *restrict x, void *restrict out, size_t t);

#define cSHA3(bits,q) (                                         \
        q==outBytes ? bits/8 :                                  \
        q==blockBytes ? (1600-bits*2)/8 :                       \
        q==contextBytes ? sizeof(struct sha3_context) :         \
        q==InitFunc   ? (uintmax_t)SHA3_##bits##_Init :         \
        q==UpdateFunc ? (uintmax_t)SHA3_##bits##_Update :       \
        q==FinalFunc  ? (uintmax_t)SHA3_##bits##_Final :        \
        0)

#define cSHA3_224(q) cSHA3(224,q)
#define cSHA3_256(q) cSHA3(256,q)
#define cSHA3_384(q) cSHA3(384,q)
#define cSHA3_512(q) cSHA3(512,q)

uintmax_t iSHA3_224(int q);
uintmax_t iSHA3_256(int q);
uintmax_t iSHA3_384(int q);
uintmax_t iSHA3_512(int q);

#endif /* MySuiteA_sha3_h */
