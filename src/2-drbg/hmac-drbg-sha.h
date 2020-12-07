/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#ifndef MySuiteA_hmac_drbg_sha_h
#define MySuiteA_hmac_drbg_sha_h 1

#include "hmac-drbg.h"
#include "../2-mac/hmac-sha.h"

Declare_HMAC_DRBG_PRF(HMAC_SHA1, hmac_sha1_t);
Declare_HMAC_DRBG_PRF(HMAC_SHA256, hmac_sha256_t);
Declare_HMAC_DRBG_PRF(HMAC_SHA384, hmac_sha384_t);

#define cHMAC_DRBG_HMAC_SHA1(q) cHMAC_DRBG(HMAC_SHA1, q)
#define cHMAC_DRBG_HMAC_SHA256(q) cHMAC_DRBG(HMAC_SHA256, q)
#define cHMAC_DRBG_HMAC_SHA384(q) cHMAC_DRBG(HMAC_SHA384, q)

#endif /* MySuiteA_hmac_drbg_sha_h */
