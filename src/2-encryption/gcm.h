/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#ifndef MySuiteA_gcm_h
#define MySuiteA_gcm_h 1

#include "../mysuitea-common.h"

// Size being x8-bytes in ILP32, and x16-bytes in I32LP64. 
typedef struct gcm_context {
    uint32_t    H[4];
    
    // Similar to that in "sponge.h". 
    ptrdiff_t   offset;
    EncFunc_t   enc;
} gcm_t;

// see [keyed-interfaces] (in "2-mac/hmac.h" as of 2020-07-10).

#define GCM_INIT(bc)                                                    \
    ((gcm_t){ .H = {0}, .offset = sizeof(gcm_t), .enc = ENC_FUNC(bc), })

void GCM_Encrypt(gcm_t *restrict gcm,
                 const void *restrict iv, // fixed, 12 bytes. 
                 size_t alen, const void *aad,
                 size_t len, const void *in, void *out,
                 size_t tlen, void *T); // zeros tail if tlen>16. 

void *GCM_Decrypt(gcm_t *restrict gcm,
                  const void *restrict iv,
                  size_t alen, const void *aad,
                  size_t len, const void *in, void *out,
                  size_t tlen, const void *T);

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
    uintmax_t iGCM_##algo(int q);

#define cGCM(bc,q) (                                                    \
        q==keyBytes ? c##bc(q) :                                        \
        q==contextBytes ? sizeof(gcm_t) + c##bc(keyschedBytes) :        \
        q==ivBytes ? 12 : q==tagBytes ? 16 :                            \
        q==KInitFunc ? (uintmax_t)GCM_##bc##_Init :                     \
        q==AEncFunc ? (uintmax_t)GCM_Encrypt :                          \
        q==ADecFunc ? (uintmax_t)GCM_Decrypt :                          \
        0)

#endif /* MySuiteA_gcm_h */
