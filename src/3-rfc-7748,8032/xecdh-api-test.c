/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rfc-7748.h"
#include "../2-ec/curves-Mt.h"

#define PKC_CtAlgo iXECDH_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_KeyAlgo iXECDH_KeyCodec

#include "test-param-defs.c.h"

XECDH_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
};

#include "../3-pkc-test-utils/test-api-kem.c.h"
