/* DannyNiu/NJF, 2022-04-15. Public Domain. */

#ifndef MySuiteA_ccm_h
#define MySuiteA_ccm_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 2 * 2 | 4 * 2 | 8 * 2
typedef struct ccm_context {
    // Similar to that in "sponge.h".
    ptrdiff_t   offset;
    EncFunc_t   enc;
} ccm_t;

// see [keyed-interfaces] (in "2-mac/hmac.h" as of 2020-07-10).

#define CCM_INIT(bc)                            \
    ((ccm_t){                                   \
        .offset = sizeof(ccm_t),                \
        .enc = ENC_FUNC(bc),                    \
    })

void *CCM_Encrypt(ccm_t *restrict ccm,
                  size_t ivlen, void const *iv, // fixed, 12 bytes.
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void *T); // zeros tail if tlen>16.

void *CCM_Decrypt(ccm_t *restrict ccm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void const *T);

#define Declare_CCM_Blockcipher(algo,name)      \
    typedef struct {                            \
        ccm_t ccm;                              \
        uint8_t kschd[KSCHD_BYTES(c##algo)];    \
    } ccm_##name;                               \
                                                \
    void *CCM_##algo##_Init(                    \
        ccm_##name *restrict x,                 \
        void const *restrict key,               \
        size_t klen);                           \
                                                \
    IntPtr iCCM_##algo(int q);

#define cCCM(bc,q) (                                                    \
        q==keyBytes ? c##bc(q) :                                        \
        q==contextBytes ? (IntPtr)(sizeof(ccm_t) + c##bc(keyschedBytes)) : \
        q==ivBytes ? -13 : q==tagBytes ? -16 :                          \
        0)

#define xCCM(bc,q) (                                                    \
        q==KInitFunc ? (IntPtr)CCM_##bc##_Init :                        \
        q==AEncFunc ? (IntPtr)CCM_Encrypt :                             \
        q==ADecFunc ? (IntPtr)CCM_Decrypt :                             \
        cCCM(bc,q) )

IntPtr tCCM(const CryptoParam_t *P, int q);

void *CCM_T_Init(
    const CryptoParam_t *restrict P,
    ccm_t *restrict x,
    void const *restrict k,
    size_t klen);

#endif /* MySuiteA_ccm_h */
