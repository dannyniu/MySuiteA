/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "sm2sig-paramset.h"

static SM2SIG_Param_t Param_P256 = {
    [0].info = i_curveSM2,
    [1].info = iSM3,
    [0].param = NULL,
    [1].param = NULL,
};

PKC_Algo_Inst_t SM2SIG_P256 = {
    .secbits = 128,
    .algo = tSM2SIG,
    .param = Param_P256
};
