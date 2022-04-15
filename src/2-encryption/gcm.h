/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#ifndef MySuiteA_gcm_h
#define MySuiteA_gcm_h 1

#include "../mysuitea-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 5 | 4 * 6 | 8 * 4
typedef struct gcm_context {
    uint32_t    H[4];
    
    // Similar to that in "sponge.h". 
    ptrdiff_t   offset;
    EncFunc_t   enc;
} gcm_t;

// see [keyed-interfaces] (in "2-mac/hmac.h" as of 2020-07-10).

#define GCM_INIT(bc)                            \
    ((gcm_t){                                   \
        .H = {0},                               \
        .offset = sizeof(gcm_t),                \
        .enc = ENC_FUNC(bc),                    \
    })

void *GCM_Encrypt(gcm_t *restrict gcm,
                  size_t ivlen, void const *iv, // fixed, 12 bytes. 
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void *T); // zeros tail if tlen>16. 

void *GCM_Decrypt(gcm_t *restrict gcm,
                  size_t ivlen, void const *iv,
                  size_t alen, void const *aad,
                  size_t len, void const *in, void *out,
                  size_t tlen, void const *T);

#define Declare_GCM_Blockcipher(algo,name)      \
    typedef struct {                            \
        gcm_t gcm;                              \
        uint8_t kschd[KSCHD_BYTES(c##algo)];    \
    } gcm_##name;                               \
                                                \
    void *GCM_##algo##_Init(                    \
        gcm_##name *restrict x,                 \
        void const *restrict key,               \
        size_t klen);                           \
                                                \
    IntPtr iGCM_##algo(int q);

#define cGCM(bc,q) (                                                    \
        q==keyBytes ? c##bc(q) :                                        \
        q==contextBytes ? sizeof(gcm_t) + c##bc(keyschedBytes) :        \
        q==ivBytes ? 12 : q==tagBytes ? 16 :                            \
        0)

#define xGCM(bc,q) (                                                    \
        q==KInitFunc ? (IntPtr)GCM_##bc##_Init :                        \
        q==AEncFunc ? (IntPtr)GCM_Encrypt :                             \
        q==ADecFunc ? (IntPtr)GCM_Decrypt :                             \
        cGCM(bc,q) )

IntPtr tGCM(const CryptoParam_t *P, int q);

void *GCM_T_Init(
    const CryptoParam_t *restrict P,
    gcm_t *restrict x,
    void const *restrict k,
    size_t klen);

#endif /* MySuiteA_gcm_h */
