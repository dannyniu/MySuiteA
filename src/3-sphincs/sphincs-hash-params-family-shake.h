/* DannyNiu/NJF, 2023-11-12. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_shake_h
#define MySuiteA_sphincs_hash_params_family_shake_h 1

#include "sphincs-hash-params-family.h"
#include "../2-xof/shake.h"

void SPHINCS_HashParam_Hmsg_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

void SPHINCS_HashParam_PRF_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

void SPHINCS_HashParam_PRFmsg_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

void SPHINCS_HashParam_F_SHAKE256(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#define SPHINCS_HashParam_H_SHAKE256 SPHINCS_HashParam_F_SHAKE256
#define SPHINCS_HashParam_T_SHAKE256 SPHINCS_HashParam_F_SHAKE256

#endif /* MySuiteA_sphincs_hash_params_family_shake_h */
