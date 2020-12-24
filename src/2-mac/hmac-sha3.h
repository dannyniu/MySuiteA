/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_hmac_sha3_h
#define MySuiteA_hmac_sha3_h 1

#include "hmac.h"
#include "../2-hash/sha3.h"

Declare_HMAC_Hash(SHA3_224, sha3_224_t);
Declare_HMAC_Hash(SHA3_256, sha3_256_t);
Declare_HMAC_Hash(SHA3_384, sha3_384_t);
Declare_HMAC_Hash(SHA3_512, sha3_512_t);

#define cHMAC_SHA3_224(q) cHMAC(SHA3_224, q)
#define cHMAC_SHA3_256(q) cHMAC(SHA3_256, q)
#define cHMAC_SHA3_384(q) cHMAC(SHA3_384, q)
#define cHMAC_SHA3_512(q) cHMAC(SHA3_512, q)

#endif /* MySuiteA_hmac_sha3_h */
