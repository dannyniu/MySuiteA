/* DannyNiu/NJF, 2022-04-15. Public Domain. */

#include "ccm-aes.h"
#include "ccm.c.h"

Define_CCM_Blockcipher(AES128, aes128_t)
Define_CCM_Blockcipher(AES192, aes192_t)
Define_CCM_Blockcipher(AES256, aes256_t)
