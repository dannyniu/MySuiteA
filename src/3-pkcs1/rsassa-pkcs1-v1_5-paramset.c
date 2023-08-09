/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "rsassa-pkcs1-v1_5-paramset.h"

PKC_Algo_Inst_t RSAEncryption_With_SHA256 = {
    .secbits = 112,
    .algo = tRSAEncryptionWithHash,
    .param = PKCS1_RSA_With_SHA256,
};
