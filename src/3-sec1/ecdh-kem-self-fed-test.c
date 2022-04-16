/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "ecdh-kem.h"
#include "../2-ec/curves-secp.h"

#define PKC_Algo_Prefix ECDH_KEM

#define PKC_CtAlgo iECDH_KEM_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_Keygen ECDH_KEM_Keygen

#define PKC_Encode_PrivateKey ECDH_KEM_Encode_PrivateKey
#define PKC_Decode_PrivateKey ECDH_KEM_Decode_PrivateKey
#define PKC_Export_PublicKey ECDH_KEM_Export_PublicKey
#define PKC_Encode_PublicKey ECDH_KEM_Encode_PublicKey
#define PKC_Decode_PublicKey ECDH_KEM_Decode_PublicKey

#include "test-param-defs.c.h"

ECDH_KEM_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
};

#define kgx_decl ECC_BASE_CTX_T(cTestCurve, ECDH_HASH_NULL)
#define enx_decl ECC_BASE_CTX_T(cTestCurve, ECDH_HASH_NULL)

#define kgx_init {                              \
        .header = ECC_CTX_INIT(                 \
            ECC_Base_Ctx_Hdr_t,                 \
            xTestCurve, ECDH_HASH_NULL), }

#define enx_init {                              \
        .header = ECC_CTX_INIT(                 \
            ECC_Base_Ctx_Hdr_t,                 \
            xTestCurve, ECDH_HASH_NULL), }

#include "../3-pkc-test-utils/test-self-fed-kem.c.h"
