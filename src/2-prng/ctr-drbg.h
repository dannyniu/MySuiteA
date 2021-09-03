/* DannyNiu/NJF, 2020-11-28. Public Domain. */

#ifndef MySuiteA_ctr_drbg_h
#define MySuiteA_ctr_drbg_h 1

#include "../mysuitea-common.h"

// [!A-E-D!]: block and key sizes greater than these are unsupported!
#define CTR_DRBG_MAX_KEYSIZE 32
#define CTR_DRBG_MAX_BLKSIZE 16

typedef struct ctr_drbg_context {
    size_t          ctx_len_total;
    
    size_t          bc_blksize;
    size_t          bc_keysize;
    ptrdiff_t       kschd_offset;

    // K immediately preceds V,
    // V and K are consecutive so as to ease implementation.
    ptrdiff_t       offset_k;
    ptrdiff_t       offset_v;
    
    EncFunc_t       bc_enc;
    KschdFunc_t     bc_kschd;
} ctr_drbg_t;

#define CTR_DRBG_CTX_LEN(bc) (                                  \
        sizeof(ctr_drbg_t) +                                    \
        BLOCK_BYTES(bc) + KEY_BYTES(bc) + KSCHD_BYTES(bc)       \
        )

#define CTR_DRBG_INIT(bc)                       \
    ((ctr_drbg_t){                              \
        .ctx_len_total = CTR_DRBG_CTX_LEN(bc),  \
        .bc_blksize = BLOCK_BYTES(bc),          \
        .bc_keysize = KEY_BYTES(bc),            \
        .kschd_offset = sizeof(ctr_drbg_t),     \
        .offset_k = sizeof(ctr_drbg_t) + (      \
            KSCHD_BYTES(bc)),                   \
        .offset_v = sizeof(ctr_drbg_t) + (      \
            KSCHD_BYTES(bc) + KEY_BYTES(bc)),   \
        .bc_enc = ENC_FUNC(bc),                 \
        .bc_kschd = KSCHD_FUNC(bc),             \
    })

void CTR_DRBG_Seed( // NIST calls this "instantiate".
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

void CTR_DRBG_Reseed(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

void CTR_DRBG_Generate(
    ctr_drbg_t *restrict x,
    void *restrict out,
    size_t len);

#define Declare_CTR_DRBG_Blockcipher(algo,name)         \
    typedef union {                                     \
        ctr_drbg_t ctr_drbg;                            \
        uint8_t blob[CTR_DRBG_CTX_LEN(c##algo)];        \
    } ctr_drbg_##name;                                  \
                                                        \
    void *CTR_DRBG_##algo##_InstInit(                   \
        ctr_drbg_##name *restrict x,                    \
        void const *restrict seedstr,                   \
        size_t len);                                    \
                                                        \
    IntPtr iCTR_DRBG_##algo(int q);

/* Notes on derivation function:
 *
 * Developers using this library may, for desiring more compact code size, 
 * omit the derivation function by defining CTR_DRBG_OMIT_DF as true.
 *
 * The derivation function in CTR-DRBG is essentially a entropy conditioner 
 * that condenses the input and reduce statistic biases.
 */

#if ! CTR_DRBG_OMIT_DF

void CTR_DRBG_Seed_WithDF(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

void CTR_DRBG_Reseed_WithDF(
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

#define cCTR_DRBG(bc,q) (                                       \
        q==contextBytes ? CTR_DRBG_CTX_LEN(c##bc) :             \
        q==seedBytes ? ((IntPtr)-1) :                           \
        0)

#else

#define cCTR_DRBG(bc,q) (                                       \
        q==contextBytes ? CTR_DRBG_CTX_LEN(c##bc) :             \
        q==seedBytes ? BLOCK_BYTES(c##bc) + KEY_BYTES(c##bc) :  \
        0)

#endif /* ! CTR_DRBG_OMIT_DF */

#define xCTR_DRBG(bc,q) (                                       \
        q==InstInitFunc ? (IntPtr)CTR_DRBG_##bc##_InstInit :    \
        q==ReseedFunc ? (IntPtr)CTR_DRBG_Reseed :               \
        q==GenFunc ? (IntPtr)CTR_DRBG_Generate :                \
        cCTR_DRBG(bc,q) )

IntPtr tCTR_DRBG(const CryptoParam_t *P, int q);

void *CTR_DRBG_T_InstInit(
    const CryptoParam_t *restrict P,
    ctr_drbg_t *restrict x,
    void const *restrict seedstr,
    size_t len);

#endif /* MySuiteA_ctr_drbg_h */
