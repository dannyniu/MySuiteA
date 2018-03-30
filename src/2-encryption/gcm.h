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

#define GCM_INIT(bc)                                                    \
    ((gcm_t){ .H = {}, .offset = sizeof(gcm_t), .enc = ENC_FUNC(bc), })

void GCM_Encrypt(gcm_t *restrict gcm,
                 void *restrict iv, // fixed, 12 bytes. 
                 size_t alen, const void *aad,
                 size_t len, const void *in, void *out,
                 size_t tlen, void *T); // zeros tail if tlen>16. 

void *GCM_Decrypt(gcm_t *restrict gcm,
                  void *restrict iv,
                  size_t alen, const void *aad,
                  size_t len, const void *in, void *out,
                  size_t tlen, const void *T);

#endif /* MySuiteA_gcm_h */
