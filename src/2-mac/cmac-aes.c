/* DannyNiu/NJF, 2021-07-22. Public Domain. */

#include "cmac-aes.h"
#include "cmac.c.h"

Define_CMAC_Blockcipher(AES128, aes128_t);
Define_CMAC_Blockcipher(AES192, aes192_t);
Define_CMAC_Blockcipher(AES256, aes256_t);
