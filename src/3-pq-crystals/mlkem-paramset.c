/* DannyNiu/NJF, 2023-10-25. Public Domain. */

#include "mlkem-paramset.h"

static MLKEM_Param_t Param_K512 = {
    [0].info = NULL,
    [0].aux = 2,
};

static MLKEM_Param_t Param_K768 = {
    [0].info = NULL,
    [0].aux = 3,
};

static MLKEM_Param_t Param_K1024 = {
    [0].info = NULL,
    [0].aux = 4,
};

PKC_Algo_Inst_t MLKEM_512 = {
    .secbits = 128,
    .algo = tMLKEM,
    .param = Param_K512
};

PKC_Algo_Inst_t MLKEM_768 = {
    .secbits = 192,
    .algo = tMLKEM,
    .param = Param_K768
};

PKC_Algo_Inst_t MLKEM_1024 = {
    .secbits = 256,
    .algo = tMLKEM,
    .param = Param_K1024
};
