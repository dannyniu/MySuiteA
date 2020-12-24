/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "hmac-sha3.h"
#include "hmac.c.h"

Define_HMAC_Hash(SHA3_224, sha3_224_t);
Define_HMAC_Hash(SHA3_256, sha3_256_t);
Define_HMAC_Hash(SHA3_384, sha3_384_t);
Define_HMAC_Hash(SHA3_512, sha3_512_t);
