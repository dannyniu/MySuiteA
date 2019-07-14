/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_hmac_h
#define MySuiteA_hmac_h 1

#include "../mysuitea-common.h"

// The structure size is a multiply of 16
// under ILP32 and I32LP64 environments. 
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

#define HMAC_INIT(hash)                         \
    ((hmac_t){                                  \
        .K0 = {0}, .tag = {0},                  \
            .B = BLOCK_BYTES(hash),             \
            .L = OUT_BYTES(hash),               \
            .finalized = 0,                     \
            .pad1 = 0,                          \
            .offset = sizeof(hmac_t),           \
            .hInit = INIT_FUNC(hash),           \
            .hUpdate = UPDATE_FUNC(hash),       \
            .hFinal = FINAL_FUNC(hash),         \
    })

// interface type / initializer type | key-dependent | key-independent
// ----------------------------------+---------------+----------------
// uninstantiated constructs         | *_SetKey (f)  | *_INIT (m)
// keyed instances                   | *_Init (f)    | N/A
// keyless/unkeyed instances         | N/A           | *_Init (f)

void HMAC_SetKey(hmac_t *restrict hmac, const void *restrict key, size_t keylen);
void HMAC_Update(hmac_t *restrict hmac, const void *restrict data, size_t len);
void HMAC_Final(hmac_t *restrict hmac, void *restrict out, size_t t);

#endif /* MySuiteA_hmac_h */
