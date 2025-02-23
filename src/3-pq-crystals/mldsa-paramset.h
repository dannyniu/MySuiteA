/* DannyNiu/NJF, 2023-10-04. Public Domain. */

#ifndef MySuiteA_mldsa_paramset_h
#define MySuiteA_mldsa_paramset_h 1

#include "mldsa.h"
#include "../2-hash/sha.h"

// Pure variants - i.e. no pre-hash.
extern PKC_Algo_Inst_t MLDSA44, MLDSA65, MLDSA87;

// Pre-Hash variants with OIDs defined as of 2024-10-22.
extern PKC_Algo_Inst_t MLDSA44_SHA512, MLDSA65_SHA512, MLDSA87_SHA512;

#endif /* MySuiteA_mldsa_paramset_h */
