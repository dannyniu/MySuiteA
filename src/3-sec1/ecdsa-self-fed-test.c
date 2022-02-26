/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "ecdsa.h"
#include "../2-ec/curves-secp.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix ECDSA
#define MSGMAX 96

#define PKC_Keygen ECDSA_Keygen

#define PKC_Encode_PrivateKey ECDSA_Encode_PrivateKey
#define PKC_Decode_PrivateKey ECDSA_Decode_PrivateKey
#define PKC_Export_PublicKey ECDSA_Export_PublicKey
#define PKC_Encode_PublicKey ECDSA_Encode_PublicKey
#define PKC_Decode_PublicKey ECDSA_Decode_PublicKey

#include "test-param-defs.c.h"

ECDSA_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#define kgx_decl SEC1_HASH_CTX_T(cTestCurve, cTestHash)
#define enx_decl SEC1_HASH_CTX_T(cTestCurve, cTestHash)

#define kgx_init {                              \
        .header = SEC1_CTX_INIT(                \
            SEC1_Hash_Ctx_Hdr_t,                \
            xTestCurve, xTestHash), }

#define enx_init {                              \
        .header = SEC1_CTX_INIT(                \
            SEC1_Hash_Ctx_Hdr_t,                \
            xTestCurve, xTestHash), }

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
