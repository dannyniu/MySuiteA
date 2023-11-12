/* DannyNiu/NJF, 2023-10-04. Public Domain. */

#include "mldsa.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix MLDSA
#define MSGMAX 96

#define PKC_Keygen MLDSA_Keygen

#define PKC_Encode_PrivateKey MLDSA_Encode_PrivateKey
#define PKC_Decode_PrivateKey MLDSA_Decode_PrivateKey
#define PKC_Export_PublicKey MLDSA_Export_PublicKey
#define PKC_Encode_PublicKey MLDSA_Encode_PublicKey
#define PKC_Decode_PublicKey MLDSA_Decode_PublicKey

MLDSA_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
    [1] = { .info = NULL, .aux = LatticeL, },
};

#define kgx_decl MLDSA_PRIV_CTX_T(LatticeK, LatticeL)
#define enx_decl MLDSA_PUB_CTX_T(LatticeK, LatticeL)

#define kgx_init {                              \
        .header = MLDSA_PRIV_CTX_INIT(          \
            LatticeK, LatticeL), }

#define enx_init {                              \
        .header = MLDSA_PUB_CTX_INIT(           \
            LatticeK, LatticeL), }

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
