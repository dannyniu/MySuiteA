/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_sha512_h
#define MySuiteA_sphincs_hash_params_family_sha512_h 1

#include "sphincs-hash-params-family-sha2-common.h"

void SPHINCS_HashParam_Hmsg_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

// PRF(...) is based on SHA-256.

void SPHINCS_HashParam_PRFmsg_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

// F(...) is based on SHA-256.
void SPHINCS_HashParam_H_SHA512(
    bufvec_t *restrict in, void *restrict out, size_t outlen);
#define SPHINCS_HashParam_T_SHA512 SPHINCS_HashParam_H_SHA512

#endif /* MySuiteA_sphincs_hash_params_family_sha512_h */
