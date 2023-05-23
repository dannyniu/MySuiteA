/* DannyNiu/NJF, 2020-11-28. Public Domain. */

#ifndef MySuiteA_hmac_drbg_h
#define MySuiteA_hmac_drbg_h 1

#include "../mysuitea-common.h"

/* was:
 * typedef struct hmac_drbg_context {
 * size_t          ctx_len_total;
 *
 * size_t          prf_outlen;
 * ptrdiff_t       offset_k;
 * ptrdiff_t       offset_v;
 *
 * ptrdiff_t       prf_ctx_offset;
 * KInitFunc_t     prf_init;
 * UpdateFunc_t    prf_update;
 * FinalFunc_t     prf_final;
 * } hmac_drbg_t;
 */

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 8 * 2 | 8 * 4 | 8 * 8
typedef struct hmac_drbg_context {
    ptrdiff_t       offset_k;
    ptrdiff_t       offset_v;

    union
    {
        struct {
            uint8_t     prf_outlen;
            uint8_t     prf_blklen;
        };
        size_t          struct_pad;
    };

    ptrdiff_t           prf_ctx_offset;
    const CryptoParam_t *parameterization;
    union
    {
        KInitFunc_t     prf_init;
        PKInitFunc_t    prf_pinit;
    };

    UpdateFunc_t    prf_update;
    FinalFunc_t     prf_final;
} hmac_drbg_t;

#define HMAC_DRBG_CTX_LEN(prf)                                          \
    (sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 2 + CTX_BYTES_1(prf))

#define HMAC_DRBG_INIT(prf)                                             \
    ((hmac_drbg_t){                                                     \
        .offset_k = sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 0,           \
        .offset_v = sizeof(hmac_drbg_t) + OUT_BYTES(prf) * 1,           \
        .prf_outlen = OUT_BYTES(prf),                                   \
        .prf_blklen = BLOCK_BYTES(prf),                                 \
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
    IntPtr iHMAC_DRBG_##algo(int q);

#define cHMAC_DRBG(prf,q) (                                     \
        q==contextBytes ? HMAC_DRBG_CTX_LEN(c##prf) :           \
        q==seedBytes ? ((IntPtr)-1) :                           \
        0)

#define xHMAC_DRBG(prf,q) (                                     \
        q==InstInitFunc ? (IntPtr)HMAC_DRBG_##prf##_InstInit :  \
        q==ReseedFunc ? (IntPtr)HMAC_DRBG_Reseed :              \
        q==GenFunc ? (IntPtr)HMAC_DRBG_Generate :               \
        cHMAC_DRBG(prf,q) )

IntPtr tHMAC_DRBG(const CryptoParam_t *P, int q);

void *HMAC_DRBG_T_InstInit(
    const CryptoParam_t *restrict P,
    hmac_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

#endif /* MySuiteA_hmac_drbg_h */
