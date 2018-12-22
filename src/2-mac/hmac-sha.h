/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_hmac_sha_h
#define MySuiteA_hmac_sha_h 1

#include "hmac.h"
#include "../2-hash/sha.h"
#include "../2-hash/sha3.h"

#define Declare_HMAC_SHA(inst)                                  \
    typedef struct {                                            \
        hmac_t hmac;                                            \
        sha##inst##_t sha;                                      \
    } HMAC_SHA##inst##_t;                                       \
                                                                \
    void HMAC_SHA##inst##_Init(HMAC_SHA##inst##_t *restrict x,  \
                               const void *restrict key,        \
                               size_t keylen);

Declare_HMAC_SHA(1)

Declare_HMAC_SHA(224)
Declare_HMAC_SHA(256)
Declare_HMAC_SHA(384)
Declare_HMAC_SHA(512)

Declare_HMAC_SHA(3_224)
Declare_HMAC_SHA(3_256)
Declare_HMAC_SHA(3_384)
Declare_HMAC_SHA(3_512)

#endif /* MySuiteA_hmac_sha_h */
