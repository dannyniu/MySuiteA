/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#ifndef MySuiteA_ctr_drbg_aes_h
#define MySuiteA_ctr_drbg_aes_h 1

#include "ctr-drbg.h"
#include "../1-symm/rijndael.h"

Declare_CTR_DRBG_Blockcipher(AES128, aes128_t); // aes*_t types actually
Declare_CTR_DRBG_Blockcipher(AES192, aes192_t); // don't exist. these are
Declare_CTR_DRBG_Blockcipher(AES256, aes256_t); // for code consistency.

#define cCTR_DRBG_AES128(q) cCTR_DRBG(AES128, q)
#define cCTR_DRBG_AES192(q) cCTR_DRBG(AES192, q)
#define cCTR_DRBG_AES256(q) cCTR_DRBG(AES256, q)

#define xCTR_DRBG_AES128(q) xCTR_DRBG(AES128, q)
#define xCTR_DRBG_AES192(q) xCTR_DRBG(AES192, q)
#define xCTR_DRBG_AES256(q) xCTR_DRBG(AES256, q)

#endif /* MySuiteA_ctr_drbg_aes_h */
