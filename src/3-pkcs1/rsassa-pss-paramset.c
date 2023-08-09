/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "rsassa-pss-paramset.h"

PKC_Algo_Inst_t RSASSA_PSS_SHA256 = {
    .secbits = 112,
    .algo = tRSASSA_PSS,
    .param = PKCS1_RSA_With_SHA256,
};

PKC_Algo_Inst_t RSASSA_PSS_SHAKE128 = {
    .secbits = 112,
    .algo = tRSASSA_PSS,
    .param = PKCS1_RSA_With_SHAKE128,
};
