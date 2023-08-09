/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "rfc-7748-paramset.h"

static XECDH_Param_t Param25519 = {
    [0].info = iX25519,
    [0].param = NULL,
};

static XECDH_Param_t Param448 = {
    [0].info = iX448,
    [0].param = NULL,
};

PKC_Algo_Inst_t RFC_7748_X25519 = {
    .secbits = 128,
    .algo = tXECDH,
    .param = Param25519,
};

PKC_Algo_Inst_t RFC_7748_X448 = {
    .secbits = 224,
    .algo = tXECDH,
    .param = Param448,
};
