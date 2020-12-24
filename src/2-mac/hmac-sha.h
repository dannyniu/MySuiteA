/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_hmac_sha_h
#define MySuiteA_hmac_sha_h 1

#include "hmac.h"
#include "../2-hash/sha.h"

Declare_HMAC_Hash(SHA1, sha1_t);
Declare_HMAC_Hash(SHA224, sha224_t);
Declare_HMAC_Hash(SHA256, sha256_t);
Declare_HMAC_Hash(SHA384, sha384_t);
Declare_HMAC_Hash(SHA512, sha512_t);

#define cHMAC_SHA1(q) cHMAC(SHA1, q)
#define cHMAC_SHA224(q) cHMAC(SHA224, q)
#define cHMAC_SHA256(q) cHMAC(SHA256, q)
#define cHMAC_SHA384(q) cHMAC(SHA384, q)
#define cHMAC_SHA512(q) cHMAC(SHA512, q)

#endif /* MySuiteA_hmac_sha_h */
