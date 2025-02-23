/* DannyNiu/NJF, 2023-10-04. Public Domain. */

#include "mldsa-paramset.h"

static MLDSA_Param_t Param_44 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iCryptoObj_Null,
    [0].aux = 4,
    [1].aux = 4,
    [2].aux = 0,
};

static MLDSA_Param_t Param_65 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iCryptoObj_Null,
    [0].aux = 6,
    [1].aux = 5,
    [2].aux = 0,
};

static MLDSA_Param_t Param_87 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iCryptoObj_Null,
    [0].aux = 8,
    [1].aux = 7,
    [2].aux = 0,
};

PKC_Algo_Inst_t MLDSA44 = {
    .secbits = 128,
    .algo = tMLDSA,
    .param = Param_44
};

PKC_Algo_Inst_t MLDSA65 = {
    .secbits = 192,
    .algo = tMLDSA,
    .param = Param_65
};

PKC_Algo_Inst_t MLDSA87 = {
    .secbits = 256,
    .algo = tMLDSA,
    .param = Param_87
};

static MLDSA_Param_t Param_44_SHA512 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iSHA512,
    [0].aux = 4,
    [1].aux = 4,
    [2].aux = 0,
};

static MLDSA_Param_t Param_65_SHA512 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iSHA512,
    [0].aux = 6,
    [1].aux = 5,
    [2].aux = 0,
};

static MLDSA_Param_t Param_87_SHA512 = {
    [0].info = NULL,
    [1].info = NULL,
    [2].info = iSHA512,
    [0].aux = 8,
    [1].aux = 7,
    [2].aux = 0,
};

PKC_Algo_Inst_t MLDSA44_SHA512 = {
    .secbits = 128,
    .algo = tMLDSA,
    .param = Param_44_SHA512
};

PKC_Algo_Inst_t MLDSA65_SHA512 = {
    .secbits = 192,
    .algo = tMLDSA,
    .param = Param_65_SHA512
};

PKC_Algo_Inst_t MLDSA87_SHA512 = {
    .secbits = 256,
    .algo = tMLDSA,
    .param = Param_87_SHA512
};
