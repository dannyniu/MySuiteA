/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"

#define PKC_CtAlgo iSLHDSA_CtCodec
#define MSGMAX 96

#define PKC_KeyAlgo iSLHDSA_KeyCodec

SLHDSA_Param_t params = {
    [0] = { .info = NULL, .aux = HashN, },
    [1] = { .info = NULL, .aux = HashH, },
    [2] = { .info = NULL, .aux = HashN == 16 ?
            (IntPtr)SPHINCS_HashParam_Hmsg_SHA256 :
            (IntPtr)SPHINCS_HashParam_Hmsg_SHA512, },
    [3] = { .info = NULL, .aux = (IntPtr)SPHINCS_HashParam_PRF_SHA2, },
    [4] = { .info = NULL, .aux = HashH == 16 ?
            (IntPtr)SPHINCS_HashParam_PRFmsg_SHA256 :
            (IntPtr)SPHINCS_HashParam_PRFmsg_SHA512, },
    [5] = { .info = NULL, .aux = (IntPtr)SPHINCS_HashParam_F_SHA2, },
    [6] = { .info = NULL, .aux = HashH == 16 ?
            (IntPtr)SPHINCS_HashParam_H_SHA256 :
            (IntPtr)SPHINCS_HashParam_H_SHA512, },
    [7] = { .info = NULL, .aux = HashH == 16 ?
            (IntPtr)SPHINCS_HashParam_T_SHA256 :
            (IntPtr)SPHINCS_HashParam_T_SHA512, },
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
