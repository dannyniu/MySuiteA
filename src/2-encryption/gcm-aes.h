/* DannyNiu/NJF, 2018-02-14. Public Domain. */
// May Trump find love in world. 

#ifndef MySuiteA_gcm_aes_h
#define MySuiteA_gcm_aes_h 1

#include "gcm.h"
#include "../1-symm/rijndael.h"

typedef struct {
    gcm_t       gcm;
    uint8_t     kschd[KSCHD_BYTES(cAES128)];
} gcm_aes128_t;

typedef struct {
    gcm_t       gcm;
    uint8_t     kschd[KSCHD_BYTES(cAES192)];
} gcm_aes192_t;

typedef struct {
    gcm_t       gcm;
    uint8_t     kschd[KSCHD_BYTES(cAES256)];
} gcm_aes256_t;

void GCM_AES128_Init(void *restrict x, const void *restrict K);
void GCM_AES192_Init(void *restrict x, const void *restrict K);
void GCM_AES256_Init(void *restrict x, const void *restrict K);

#ifdef foo
# // emacs indenting aid.
#endif /* foo */

#define cGCM_AES(bits,q) (                                              \
        q==keyBytes ? bits/8 :                                          \
        q==contextBytes ? sizeof(gcm_t) + cAES(bits,keyschedBytes) :    \
        q==ivBytes ? 12 : q==tagBytes ? 16 :                            \
        q==KInitFunc ? (uintptr_t)GCM_AES##bits##_Init :                \
        q==AEncFunc ? (uintptr_t)GCM_Encrypt :                          \
        q==ADecFunc ? (uintptr_t)GCM_Decrypt :                          \
        0)

#define cGCM_AES128(q) cGCM_AES(128,q)
#define cGCM_AES192(q) cGCM_AES(192,q)
#define cGCM_AES256(q) cGCM_AES(256,q)

uintptr_t iGCM_AES128(int q);
uintptr_t iGCM_AES192(int q);
uintptr_t iGCM_AES256(int q);

#endif /* MySuiteA_gcm_aes_h */
