/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#include "hmac-drbg-sha.h"
#include "hmac-drbg.c.h"

Define_HMAC_DRBG_PRF(HMAC_SHA1, hmac_sha1_t);
Define_HMAC_DRBG_PRF(HMAC_SHA256, hmac_sha256_t);
Define_HMAC_DRBG_PRF(HMAC_SHA384, hmac_sha384_t);
