/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "ecdsa.h"
#include "../2-ec/curves-secp.h"
#include "../2-hash/sha.h"

#define PKC_InstAlgo tECDSA
#define PKC_CtAlgo iECDSA_CtCodec
#define PKC_KeyAlgo iECDSA_KeyCodec
#define MSGMAX 96

#include "test-param-defs.c.h"

ECDSA_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
