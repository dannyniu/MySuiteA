/* DannyNiu/NJF, 2022-04-15. Public Domain. */

#ifndef MySuiteA_ccm_aes_h
#define MySuiteA_ccm_aes_h 1

#include "ccm.h"
#include "../1-symm/rijndael.h"

Declare_CCM_Blockcipher(AES128, aes128_t);
Declare_CCM_Blockcipher(AES192, aes192_t);
Declare_CCM_Blockcipher(AES256, aes256_t);

#define cCCM_AES128(q) cCCM(AES128,q)
#define cCCM_AES192(q) cCCM(AES192,q)
#define cCCM_AES256(q) cCCM(AES256,q)

#define xCCM_AES128(q) xCCM(AES128,q)
#define xCCM_AES192(q) xCCM(AES192,q)
#define xCCM_AES256(q) xCCM(AES256,q)

#endif /* MySuiteA_ccm_aes_h */
