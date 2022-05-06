/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "eddsa.h"
#include "../2-ec/curves-Ed.h"
#include "../2-hash/sha.h"
#include "../2-hash/sha3.h"
#include "../2-xof/shake.h"

#define PKC_Algo_Prefix EdDSA
#define MSGMAX 96

#define PKC_Keygen EdDSA_Keygen

#define PKC_Encode_PrivateKey EdDSA_Encode_PrivateKey
#define PKC_Decode_PrivateKey EdDSA_Decode_PrivateKey
#define PKC_Export_PublicKey EdDSA_Export_PublicKey
#define PKC_Encode_PublicKey EdDSA_Encode_PublicKey
#define PKC_Decode_PublicKey EdDSA_Decode_PublicKey

#include "test-param-defs.c.h"

EdDSA_Param_t params = {
    [0] = { .info = iTestCurve, .param = NULL, },
    [1] = { .info = iTestHash,  .param = NULL, },
};

#define kgx_decl EDDSA_CTX_T(cTestCurve, cTestHash)
#define enx_decl EDDSA_CTX_T(cTestCurve, cTestHash)

#define kgx_init {                              \
        .header = EDDSA_CTX_INIT(               \
            xTestCurve, xTestHash), }

#define enx_init {                              \
        .header = EDDSA_CTX_INIT(               \
            xTestCurve, xTestHash), }

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
