/* DannyNiu/NJF, 2018-02-14. Public Domain */

#include "gcm-aes.h"
#include "gcm.c.h"

Define_GCM_Blockcipher(AES128, aes128_t)
Define_GCM_Blockcipher(AES192, aes192_t)
Define_GCM_Blockcipher(AES256, aes256_t)
