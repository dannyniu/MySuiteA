/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "sm2sig.h"
#include "../2-ec/curveSM2.h"
#include "../2-hash/sm3.h"

#define PKC_InstAlgo tSM2SIG
#define PKC_CtAlgo iSM2SIG_CtCodec
#define PKC_KeyAlgo iSM2SIG_KeyCodec
#define MSGMAX 96

#include "test-param-defs.c.h"

SM2SIG_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
