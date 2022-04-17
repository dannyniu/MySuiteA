/* DannyNiu/NJF, 2018-02-14. Public Domain. */
// May Trump find love in world.

#ifndef MySuiteA_gcm_aes_h
#define MySuiteA_gcm_aes_h 1

#include "gcm.h"
#include "../1-symm/rijndael.h"

Declare_GCM_Blockcipher(AES128, aes128_t);
Declare_GCM_Blockcipher(AES192, aes192_t);
Declare_GCM_Blockcipher(AES256, aes256_t);

#define cGCM_AES128(q) cGCM(AES128,q)
#define cGCM_AES192(q) cGCM(AES192,q)
#define cGCM_AES256(q) cGCM(AES256,q)

#define xGCM_AES128(q) xGCM(AES128,q)
#define xGCM_AES192(q) xGCM(AES192,q)
#define xGCM_AES256(q) xGCM(AES256,q)

#endif /* MySuiteA_gcm_aes_h */
