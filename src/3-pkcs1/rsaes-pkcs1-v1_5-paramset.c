/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "rsaes-pkcs1-v1_5-paramset.h"

PKC_Algo_Inst_t RSAEncryptionParam = {
    .secbits = 112,
    .algo = tRSAEncryption,
    .param = PKCS1_RSA_With_SHA256,
};
