/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "mldsa.h"

#define PKC_CtAlgo iMLDSA_CtCodec
#define MSGMAX 96

#define PKC_KeyAlgo iMLDSA_KeyCodec

MLDSA_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
    [1] = { .info = NULL, .aux = LatticeL, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
