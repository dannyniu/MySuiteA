/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_sha2_common_h
#define MySuiteA_sphincs_hash_params_family_sha2_common_h 1

#include "sphincs-hash-params-family.h"

void SPHINCS_Hash_Comp_ADRS(
    UpdateFunc_t updatefunc, void *restrict hctx,
    const uint8_t *restrict ADRS);

void SPHINCS_HashParam_PRF_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

void SPHINCS_HashParam_F_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#endif /* MySuiteA_sphincs_hash_params_family_sha2_common_h */
