/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "rsaes-oaep-paramset.h"

PKC_Algo_Inst_t RSAES_OAEP_SHA256 = {
    .secbits = 112,
    .algo = tRSAES_OAEP,
    .param = PKCS1_RSA_With_SHA256,
};

PKC_Algo_Inst_t RSAES_OAEP_SHAKE128 = {
    .secbits = 112,
    .algo = tRSAES_OAEP,
    .param = PKCS1_RSA_With_SHAKE128,
};
