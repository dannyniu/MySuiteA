/* DannyNiu/NJF, 2020-11-28. Public Domain. */

#ifndef MySuiteA_hmac_drbg_h
#define MySuiteA_hmac_drbg_h 1

#include "../mysuitea-common.h"

typedef struct hmac_drbg_context {
    size_t          ctx_len_total;

    size_t          prf_outlen;
    ptrdiff_t       offset_k;
    ptrdiff_t       offset_v;
    
    ptrdiff_t       prf_ctx_offset;
    KInitFunc_t     prf_init;
    UpdateFunc_t    prf_update;
    FinalFunc_t     prf_final;
} hmac_drbg_t;

#define HMAC_DRBG_CTX_LEN(prf)                                          \
    (sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 2 + CTX_BYTES_1(prf))

#define HMAC_DRBG_INIT(prf)                                             \
    ((hmac_drbg_t){                                                     \
        .ctx_len_total = HMAC_DRBG_CTX_LEN(prf),                        \
        .prf_outlen = OUT_BYTES(prf),                                   \
        .offset_k = sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 0,           \
        .offset_v = sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 1,           \
        .prf_ctx_offset = sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 2,     \
        .prf_init = KINIT_FUNC(prf),                                    \
        .prf_update = UPDATE_FUNC(prf),                                 \
        .prf_final = FINAL_FUNC(prf),                                   \
    })

void HMAC_DRBG_Seed( // NIST calls this "instantiate".
    hmac_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

void HMAC_DRBG_Reseed(
    hmac_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

void HMAC_DRBG_Generate(
    hmac_drbg_t *restrict x,
    void *restrict out,
    size_t len);

#define Declare_HMAC_DRBG_PRF(algo,name)                \
    typedef union {                                     \
        hmac_drbg_t hmac_drbg;                          \
        uint8_t blob[HMAC_DRBG_CTX_LEN(c##algo)];       \
    } hmac_drbg_##name;                                 \
                                                        \
    void *HMAC_DRBG_##algo##_InstInit(                  \
        hmac_drbg_##name *restrict x,                   \
        void const *restrict seedstr,                   \
        size_t len);                                    \
                                                        \
    uparam_t iHMAC_DRBG_##algo(int q);

#define cHMAC_DRBG(prf,q) (                                             \
        q==contextBytes ? HMAC_DRBG_CTX_LEN(c##prf) :                   \
        q==seedBytes ? 0 :                                              \
        q==seedBytesMax ? ((uparam_t)-1) :                              \
        q==InstInitFunc ? (uparam_t)HMAC_DRBG_##prf##_InstInit :        \
        q==ReseedFunc ? (uparam_t)HMAC_DRBG_Reseed :                    \
        q==GenFunc ? (uparam_t)HMAC_DRBG_Generate :                     \
        0)

#endif /* MySuiteA_hmac_drbg_h */