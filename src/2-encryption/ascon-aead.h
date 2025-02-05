/* DannyNiu/NJF, 2025-01-28. Public Domain. */

#ifndef MySuiteA_ascon_aead_h
#define MySuiteA_ascon_aead_h 1

#include "../1-symm/ascon-permutation.h"
#include "../1-symm/sponge.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: Error | 8 *17 | 8 *18
typedef struct {
    sponge_t    sponge;
    union {
        uint8_t     u8[40];
        uint64_t    u64[5];
    } state[2];
    uint8_t key[32];
} ascon_aead_t, ascon_aead128_t;

void *Ascon_AEAD_Init(
    ascon_aead128_t *restrict ctx, void const *restrict k, size_t klen);

void *Ascon_AEAD_Encrypt(
    ascon_aead128_t *restrict ctx,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void *T);

void *Ascon_AEAD_Decrypt(
    ascon_aead128_t *restrict x,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void const *T);

#define cAscon_AEAD128(q) (                             \
        q==keyBytes ? 16 :                              \
        q==contextBytes ? sizeof(ascon_aead_t) :        \
        q==ivBytes ? 16 : q==tagBytes ? 16 :            \
        0)

#define xAscon_AEAD128(q) (                             \
        q==KInitFunc ? (IntPtr)Ascon_AEAD_Init :        \
        q==AEncFunc ? (IntPtr)Ascon_AEAD_Encrypt :      \
        q==ADecFunc ? (IntPtr)Ascon_AEAD_Decrypt :      \
        cAscon_AEAD128(q) )

IntPtr iAscon_AEAD128(int q);

#define cAscon_AEAD256(q) (                             \
        q==keyBytes ? 32 :                              \
        q==contextBytes ? sizeof(ascon_aead_t) :        \
        q==ivBytes ? 16 : q==tagBytes ? 16 :            \
        0)

#define xAscon_AEAD256(q) (                             \
        q==KInitFunc ? (IntPtr)Ascon_AEAD_Init :        \
        q==AEncFunc ? (IntPtr)Ascon_AEAD_Encrypt :      \
        q==ADecFunc ? (IntPtr)Ascon_AEAD_Decrypt :      \
        cAscon_AEAD256(q) )

IntPtr iAscon_AEAD256(int q);

#endif /* MySuiteA_ascon_aead_h */
