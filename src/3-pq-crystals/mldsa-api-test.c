/* DannyNiu/NJF, 2023-10-04. Public Domain. */

#include "mldsa.h"
#include "../2-hash/sha.h"

#define PKC_InstAlgo tMLDSA
#define PKC_CtAlgo iMLDSA_CtCodec
#define PKC_KeyAlgo iMLDSA_KeyCodec
#define MSGMAX 96

MLDSA_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
    [1] = { .info = NULL, .aux = LatticeL, },
    [2] = { .info = Hash, .aux = 0, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
