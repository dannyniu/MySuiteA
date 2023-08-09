/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "ecdh-kem-paramset.h"

static ECDH_KEM_Param_t Param_P256 = {
    [0].info = i_secp256r1,
    [0].param = NULL,
};

static ECDH_KEM_Param_t Param_P384 = {
    [0].info = i_secp384r1,
    [0].param = NULL,
};

PKC_Algo_Inst_t ECDH_KEM_P256 = {
    .secbits = 128,
    .algo = tECDH_KEM,
    .param = Param_P256
};

PKC_Algo_Inst_t ECDH_KEM_P384 = {
    .secbits = 192,
    .algo = tECDH_KEM,
    .param = Param_P384,
};
