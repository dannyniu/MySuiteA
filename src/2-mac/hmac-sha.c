/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "hmac-sha.h"
#include "hmac.c.h"

Define_HMAC_Hash(SHA1, sha1_t);
Define_HMAC_Hash(SHA224, sha224_t);
Define_HMAC_Hash(SHA256, sha256_t);
Define_HMAC_Hash(SHA384, sha384_t);
Define_HMAC_Hash(SHA512, sha512_t);
Define_HMAC_Hash(SHA3_224, sha3_224_t);
Define_HMAC_Hash(SHA3_256, sha3_256_t);
Define_HMAC_Hash(SHA3_384, sha3_384_t);
Define_HMAC_Hash(SHA3_512, sha3_512_t);
