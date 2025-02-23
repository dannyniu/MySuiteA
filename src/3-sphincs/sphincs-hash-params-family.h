/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_h
#define MySuiteA_sphincs_hash_params_family_h 1

#include "../2-hash/hash-funcs-set.h"

typedef void (*SPHINCS_HashParam_t)(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#endif /* MySuiteA_sphincs_hash_params_family_h */
