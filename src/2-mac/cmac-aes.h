/* DannyNiu/NJF, 2021-07-22. Public Domain. */

#ifndef MySuiteA_cmac_aes_h
#define MySuiteA_cmac_aes_h 1

#include "cmac.h"
#include "../1-symm/rijndael.h"

Declare_CMAC_Blockcipher(AES128, aes128_t);
Declare_CMAC_Blockcipher(AES192, aes192_t);
Declare_CMAC_Blockcipher(AES256, aes256_t);

#define cCMAC_AES128(q) cCMAC(AES128, q)
#define cCMAC_AES192(q) cCMAC(AES192, q)
#define cCMAC_AES256(q) cCMAC(AES256, q)

#define xCMAC_AES128(q) xCMAC(AES128, q)
#define xCMAC_AES192(q) xCMAC(AES192, q)
#define xCMAC_AES256(q) xCMAC(AES256, q)

#endif /* MySuiteA_cmac_aes_h */
