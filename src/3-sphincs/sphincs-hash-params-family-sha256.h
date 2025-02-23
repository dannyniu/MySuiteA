/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_sha256_h
#define MySuiteA_sphincs_hash_params_family_sha256_h 1

#include "sphincs-hash-params-family-sha2-common.h"

void SPHINCS_HashParam_Hmsg_SHA256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#define SPHINCS_HashParam_PRF_SHA256 SPHINCS_HashParam_PRF_SHA2

void SPHINCS_HashParam_PRFmsg_SHA256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#define SPHINCS_HashParam_F_SHA256 SPHINCS_HashParam_F_SHA2
#define SPHINCS_HashParam_H_SHA256 SPHINCS_HashParam_F_SHA2
#define SPHINCS_HashParam_T_SHA256 SPHINCS_HashParam_F_SHA2

#endif /* MySuiteA_sphincs_hash_params_family_sha256_h */
