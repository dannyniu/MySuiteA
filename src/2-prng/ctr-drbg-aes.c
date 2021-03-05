/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#include "ctr-drbg-aes.h"
#include "ctr-drbg.c.h"

Define_CTR_DRBG_Blockcipher(AES128, aes128_t);
Define_CTR_DRBG_Blockcipher(AES192, aes192_t);
Define_CTR_DRBG_Blockcipher(AES256, aes256_t);
