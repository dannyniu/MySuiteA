/* DannyNiu/NJF, 2023-11-04. Public Domain. */

#ifndef MySuiteA_sphincs_hash_params_family_sha2_common_h
#define MySuiteA_sphincs_hash_params_family_sha2_common_h 1

#include "sphincs-hash-params-family.h"
#include "../2-hash/sha.h"

// 2025-09-17:
// There's a trick to accelerate the computation of SLH-DSA routines in SHA-2,
// where block-padded PK.seed is saved as the domain-separation IV and reused
// and not re-calculated after initial computation. This trick is not employed
// in MySuiteA's implementation of SLH-DSA. Firstly, the working context needs
// to be saved somewhere, subroutine call stack would be preferrable, working
// context of signature scheme is also fine, but there're 2 different hash
// algorithms in security level category III and V of SLH-DSA, which adds to
// complication - saving on the working context makes the parameters more
// complex, and saving on the stack brings to the second problem: If each
// sub-signature component have a hashing working context, then it prevents
// alternative hash implementations from out side of MySuiteA being used with
// MySuiteA's implementation of SLH-DSA (even though MySuiteA aims to be
// self-contained in its own regard).

void SPHINCS_Hash_Comp_ADRS(
    UpdateFunc_t updatefunc, void *restrict hctx,
    const uint8_t *restrict ADRS);

void SPHINCS_HashParam_PRF_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

void SPHINCS_HashParam_F_SHA2(
    bufvec_t *restrict in, void *restrict out, size_t outlen);

#endif /* MySuiteA_sphincs_hash_params_family_sha2_common_h */
