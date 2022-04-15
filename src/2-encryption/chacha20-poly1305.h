/* DannyNiu/NJF, 2018-02-17. Public Domain. */

#ifndef MySuiteA_chacha20_poly1305_h
#define MySuiteA_chacha20_poly1305_h 1

#include "../mysuitea-common.h"
#include "../1-symm/chacha.h"
#include "../1-symm/poly1305.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:        4 * 31       .
typedef struct {
    uint32_t    state[16];
    poly1305_t  poly1305;
} chacha_aead_t;

void *ChaCha_AEAD_Init(
    chacha_aead_t *restrict x,
    void const *restrict K,
    size_t klen);

void *ChaCha_AEAD_Encrypt(
    chacha_aead_t *restrict x,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void *T);

void *ChaCha_AEAD_Decrypt(
    chacha_aead_t *restrict x,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void const *T);

#define cChaCha_AEAD(q) (                               \
        q==keyBytes ? 32 :                              \
        q==contextBytes ? sizeof(chacha_aead_t) :       \
        q==ivBytes ? 12 : q==tagBytes ? 16 :            \
        0)

#define xChaCha_AEAD(q) (                               \
        q==KInitFunc ? (IntPtr)ChaCha_AEAD_Init :       \
        q==AEncFunc ? (IntPtr)ChaCha_AEAD_Encrypt :     \
        q==ADecFunc ? (IntPtr)ChaCha_AEAD_Decrypt :     \
        cChaCha_AEAD(q) )

IntPtr iChaCha_AEAD(int q);

#endif
