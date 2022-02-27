/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "ecdh-kem.h"
#include "../2-ec/curves-secp.h"

#define PKC_CtAlgo iECDH_KEM_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_KeyAlgo iECDH_KEM_KeyCodec

#include "test-param-defs.c.h"

ECDH_KEM_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
};

#include "../3-pkc-test-utils/test-api-kem.c.h"
