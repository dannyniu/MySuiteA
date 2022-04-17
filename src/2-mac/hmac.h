/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_hmac_h
#define MySuiteA_hmac_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 16*21 | 16*22 | 16*23
typedef struct hmac_context {
    uint8_t     K0[256];
    uint8_t     tag[64];
    unsigned    B, L;
    int         finalized, pad1;

    // Similar to that in "sponge.h".
    ptrdiff_t       offset;
    InitFunc_t      hInit;
    UpdateFunc_t    hUpdate;
    FinalFunc_t     hFinal;
} hmac_t;

// [keyed-interfaces]
// interface type / initializer type | key-dependent | key-independent
// ----------------------------------+---------------+----------------
// uninstantiated constructs         | *_SetKey (f)  | *_INIT (m)
// keyed instances                   | *_Init (f)    | N/A
// keyless/unkeyed instances         | N/A           | *_Init (f)
// Note: (f) = function, (m) = macro evaluating to a compound literal.

#define HMAC_INIT(hash)                         \
    ((hmac_t){                                  \
        .K0 = {0}, .tag = {0},                  \
        .B = BLOCK_BYTES(hash),                 \
        .L = OUT_BYTES(hash),                   \
        .finalized = false,                     \
        .pad1 = 0,                              \
        .offset = sizeof(hmac_t),               \
        .hInit = INIT_FUNC(hash),               \
        .hUpdate = UPDATE_FUNC(hash),           \
        .hFinal = FINAL_FUNC(hash),             \
    })

void *HMAC_SetKey(
    hmac_t *restrict hmac, const void *restrict key, size_t keylen);

void HMAC_Update(
    hmac_t *restrict hmac, const void *restrict data, size_t len);

void HMAC_Final(
    hmac_t *restrict hmac, void *restrict out, size_t t);

#define Declare_HMAC_Hash(algo,name)            \
    typedef struct {                            \
        hmac_t hmac;                            \
        name hash;                              \
    } hmac_##name;                              \
                                                \
    void *HMAC_##algo##_Init(                   \
        hmac_##name *restrict x,                \
        void const *restrict key,               \
        size_t keylen);                         \
                                                \
    IntPtr iHMAC_##algo(int q);


#define cHMAC(hash,q) (                                         \
        q==outBytes || q==blockBytes ? c##hash(q) :             \
        q==keyBytes ? (IntPtr)-BLOCK_BYTES(c##hash) :           \
        q==contextBytes ? sizeof(hmac_t) + CTX_BYTES(c##hash) : \
        0)

#define xHMAC(hash,q) (                                         \
        q==KInitFunc ? (IntPtr)HMAC_##hash##_Init :             \
        q==UpdateFunc ? (IntPtr)HMAC_Update :                   \
        q==FinalFunc ? (IntPtr)HMAC_Final :                     \
        cHMAC(hash,q) )

IntPtr tHMAC(const CryptoParam_t *P, int q);

void *HMAC_T_Init(
    const CryptoParam_t *restrict P,
    hmac_t *restrict x,
    void const *restrict k,
    size_t klen);

#endif /* MySuiteA_hmac_h */
