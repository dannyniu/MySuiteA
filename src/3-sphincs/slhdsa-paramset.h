/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#ifndef MySuiteA_slhdsa_paramset_h
#define MySuiteA_slhdsa_paramset_h 1

#include "slhdsa.h"

extern PKC_Algo_Inst_t
SLHDSA_SHA2_128s,
    SLHDSA_SHA2_128f,
    SLHDSA_SHA2_192s,
    SLHDSA_SHA2_192f,
    SLHDSA_SHA2_256s,
    SLHDSA_SHA2_256f,
    SLHDSA_SHAKE_128s,
    SLHDSA_SHAKE_128f,
    SLHDSA_SHAKE_192s,
    SLHDSA_SHAKE_192f,
    SLHDSA_SHAKE_256s,
    SLHDSA_SHAKE_256f;

extern PKC_Algo_Inst_t
SLHDSA_SHA2_128s_wSHA256,
    SLHDSA_SHA2_128f_wSHA256,
    SLHDSA_SHA2_192s_wSHA512,
    SLHDSA_SHA2_192f_wSHA512,
    SLHDSA_SHA2_256s_wSHA512,
    SLHDSA_SHA2_256f_wSHA512,
    SLHDSA_SHAKE_128s_wSHAKE128,
    SLHDSA_SHAKE_128f_wSHAKE128,
    SLHDSA_SHAKE_192s_wSHAKE256,
    SLHDSA_SHAKE_192f_wSHAKE256,
    SLHDSA_SHAKE_256s_wSHAKE256,
    SLHDSA_SHAKE_256f_wSHAKE256;

#endif /* MySuiteA_slhdsa_paramset_h */
