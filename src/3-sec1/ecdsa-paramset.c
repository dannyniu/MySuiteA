/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "ecdsa-paramset.h"

static ECDSA_Param_t Param_P256 = {
    [0].info = i_secp256r1,
    [1].info = iSHA256,
    [0].param = NULL,
    [1].param = NULL,
};

static ECDSA_Param_t Param_P384 = {
    [0].info = i_secp384r1,
    [1].info = iSHA384,
    [0].param = NULL,
    [1].param = NULL,
};

PKC_Algo_Inst_t ECDSA_P256 = {
    .secbits = 128,
    .algo = tECDSA,
    .param = Param_P256
};

PKC_Algo_Inst_t ECDSA_P384 = {
    .secbits = 192,
    .algo = tECDSA,
    .param = Param_P384,
};
