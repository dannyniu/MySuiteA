/* DannyNiu/NJF, 2018-02-17. Public Domain. */

#ifndef MySuiteA_chacha20_poly1305_h
#define MySuiteA_chacha20_poly1305_h 1

#include "../mysuitea-common.h"
#include "../1-symm/chacha.h"
#include "../1-symm/poly1305.h"

// Fixed-size in all environments. 
typedef struct {
    uint32_t    state[16];
    poly1305_t  poly1305;
} chacha_aead_t;

void *ChaCha_AEAD_Init(
    chacha_aead_t *restrict x,
    void const *restrict K,
    size_t klen);

void ChaCha_AEAD_Encrypt(
    chacha_aead_t *restrict x,
    void const *restrict iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void *T);

void *ChaCha_AEAD_Decrypt(
    chacha_aead_t *restrict x,
    void const *restrict iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void const *T);

#define cChaCha_AEAD(q) (                               \
        q==keyBytes ? 32 :                              \
        q==contextBytes ? sizeof(chacha_aead_t) :       \
        q==ivBytes ? 12 : q==tagBytes ? 16 :            \
        q==KInitFunc ? (uintptr_t)ChaCha_AEAD_Init :    \
        q==AEncFunc ? (uintptr_t)ChaCha_AEAD_Encrypt :  \
        q==ADecFunc ? (uintptr_t)ChaCha_AEAD_Decrypt :  \
        0)

uintptr_t iChaCha_AEAD(int q);

#endif
