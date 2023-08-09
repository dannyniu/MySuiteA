/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "eddsa-paramset.h"

static EdDSA_Param_t Param25519 = {
    [0].info = iCurveEd25519,
    [1].info = iSHA512,
    [0].param = NULL,
    [1].param = NULL,
};

static EdDSA_Param_t Param448 = {
    [0].info = iCurveEd448,
    [1].info = iSHAKE256,
    [0].param = NULL,
    [1].param = NULL,
};

PKC_Algo_Inst_t EdDSA_Ed25519 = {
    .secbits = 128,
    .algo = tEdDSA,
    .param = Param25519,
};

PKC_Algo_Inst_t EdDSA_Ed448 = {
    .secbits = 224,
    .algo = tEdDSA,
    .param = Param448,
};
