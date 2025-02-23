/* DannyNiu/NJF, 2023-10-25. Public Domain. */

#include "mlkem.h"

#define PKC_Algo_Prefix MLKEM

#define PKC_CtAlgo iMLKEM_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_Keygen MLKEM_Keygen

#define PKC_Encode_PrivateKey MLKEM_Encode_PrivateKey
#define PKC_Decode_PrivateKey MLKEM_Decode_PrivateKey
#define PKC_Export_PublicKey MLKEM_Export_PublicKey
#define PKC_Encode_PublicKey MLKEM_Encode_PublicKey
#define PKC_Decode_PublicKey MLKEM_Decode_PublicKey

MLKEM_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
};

#define kgx_decl MLKEM_CTX_T(LatticeK)
#define enx_decl MLKEM_CTX_T(LatticeK)

#define kgx_init {                              \
        .header = MLKEM_CTX_INIT(LatticeK), }

#define enx_init {                              \
        .header = MLKEM_CTX_INIT(LatticeK), }

#include "../3-pkc-test-utils/test-self-fed-kem.c.h"
