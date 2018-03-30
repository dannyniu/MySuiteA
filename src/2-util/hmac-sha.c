/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "hmac-sha.h"

#define Define_HMAC_SHA(inst)                                   \
    void HMAC_SHA##inst##_Init(HMAC_SHA##inst##_t *restrict x,  \
                                   const void *restrict key,    \
                                   size_t keylen)               \
    {                                                           \
     x->hmac = HMAC_INIT(_iSHA##inst);                          \
     HMAC_SetKey(&x->hmac, key, keylen);                        \
     }

Define_HMAC_SHA(1)

Define_HMAC_SHA(224)
Define_HMAC_SHA(256)
Define_HMAC_SHA(384)
Define_HMAC_SHA(512)

Define_HMAC_SHA(3_224)
Define_HMAC_SHA(3_256)
Define_HMAC_SHA(3_384)
Define_HMAC_SHA(3_512)
