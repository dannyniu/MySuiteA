/* DannyNiu/NJF, 2023-08-09. Public Domain. */

#include "pkcs1-paramset-common.h"

PKCS1_RSA_Param_t PKCS1_RSA_With_SHA256 = {
    [0].info = iSHA256,
    [1].info = iSHA256,
    [2].info = NULL,
    [3].info = NULL,
    [0].param = NULL,
    [1].param = NULL,
    [2].aux = 2048,
    [3].aux = 2,
};

PKCS1_RSA_Param_t PKCS1_RSA_With_SHAKE128 = {
    [0].info = iSHAKE128,
    [1].info = iSHAKE128,
    [2].info = NULL,
    [3].info = NULL,
    [0].param = NULL,
    [1].param = NULL,
    [2].aux = 2048,
    [3].aux = 2,
};
