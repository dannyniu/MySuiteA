/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "eddsa.h"
#include "../2-ec/curves-Ed.h"
#include "../2-hash/sha.h"
#include "../2-hash/sha3.h"
#include "../2-xof/shake.h"

#define PKC_CtAlgo iEdDSA_CtCodec
#define MSGMAX 96

#define PKC_KeyAlgo iEdDSA_KeyCodec

#include "test-param-defs.c.h"

EdDSA_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
