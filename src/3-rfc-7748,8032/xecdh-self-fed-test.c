/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rfc-7748.h"
#include "../2-ec/curves-Mt.h"

#define PKC_Algo_Prefix XECDH

#define PKC_CtAlgo iXECDH_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_Keygen XECDH_Keygen

#define PKC_Encode_PrivateKey XECDH_Encode_PrivateKey
#define PKC_Decode_PrivateKey XECDH_Decode_PrivateKey
#define PKC_Export_PublicKey XECDH_Export_PublicKey
#define PKC_Encode_PublicKey XECDH_Encode_PublicKey
#define PKC_Decode_PublicKey XECDH_Decode_PublicKey

#include "test-param-defs.c.h"

XECDH_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
};

#define kgx_decl XECDH_CTX_T(cTestCurve)
#define enx_decl XECDH_CTX_T(cTestCurve)

#define kgx_init { .header = XECDH_CTX_HDR_INIT(xTestCurve), }
#define enx_init { .header = XECDH_CTX_HDR_INIT(xTestCurve), }

#include "../3-pkc-test-utils/test-self-fed-kem.c.h"
