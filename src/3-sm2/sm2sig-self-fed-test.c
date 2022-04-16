/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "sm2sig.h"
#include "../2-ec/curveSM2.h"
#include "../2-hash/sm3.h"

#define PKC_Algo_Prefix SM2SIG
#define MSGMAX 96

#define PKC_Keygen SM2SIG_Keygen

#define PKC_Encode_PrivateKey SM2SIG_Encode_PrivateKey
#define PKC_Decode_PrivateKey SM2SIG_Decode_PrivateKey
#define PKC_Export_PublicKey SM2SIG_Export_PublicKey
#define PKC_Encode_PublicKey SM2SIG_Encode_PublicKey
#define PKC_Decode_PublicKey SM2SIG_Decode_PublicKey

#include "test-param-defs.c.h"

SM2SIG_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#define kgx_decl ECC_HASH_CTX_T(cTestCurve, cTestHash)
#define enx_decl ECC_HASH_CTX_T(cTestCurve, cTestHash)

#define kgx_init {                              \
        .header = ECC_CTX_INIT(                 \
            ECC_Hash_Ctx_Hdr_t,                 \
            xTestCurve, xTestHash), }

#define enx_init {                              \
        .header = ECC_CTX_INIT(                 \
            ECC_Hash_Ctx_Hdr_t,                 \
            xTestCurve, xTestHash), }

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
