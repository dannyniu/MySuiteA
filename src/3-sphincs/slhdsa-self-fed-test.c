/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix SLHDSA
#define MSGMAX 96

#define PKC_Keygen SLHDSA_Keygen

#define PKC_Encode_PrivateKey SLHDSA_Encode_PrivateKey
#define PKC_Decode_PrivateKey SLHDSA_Decode_PrivateKey
#define PKC_Export_PublicKey SLHDSA_Export_PublicKey
#define PKC_Encode_PublicKey SLHDSA_Encode_PublicKey
#define PKC_Decode_PublicKey SLHDSA_Decode_PublicKey

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

#define kgx_decl SLHDSA_CTX_T(HashN, HashH)
#define enx_decl SLHDSA_CTX_T(HashN, HashH)

#define kgx_init {                                                      \
        .header = SLHDSA_CTX_INIT(                                      \
            HashN, HashH,                                               \
            (HashN == 16 ?                                              \
             SPHINCS_HashParam_Hmsg_SHA256 :                            \
             SPHINCS_HashParam_Hmsg_SHA512),                            \
            SPHINCS_HashParam_PRF_SHA2,                                 \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_PRFmsg_SHA256 :                          \
             SPHINCS_HashParam_PRFmsg_SHA512),                          \
            SPHINCS_HashParam_F_SHA2,                                   \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_H_SHA256 :                               \
             SPHINCS_HashParam_H_SHA512),                               \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_T_SHA256 :                               \
             SPHINCS_HashParam_T_SHA512)                                \
            ), }

#define enx_init {                                                      \
        .header = SLHDSA_CTX_INIT(                                      \
            HashN, HashH,                                               \
            (HashN == 16 ?                                              \
             SPHINCS_HashParam_Hmsg_SHA256 :                            \
             SPHINCS_HashParam_Hmsg_SHA512),                            \
            SPHINCS_HashParam_PRF_SHA2,                                 \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_PRFmsg_SHA256 :                          \
             SPHINCS_HashParam_PRFmsg_SHA512),                          \
            SPHINCS_HashParam_F_SHA2,                                   \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_H_SHA256 :                               \
             SPHINCS_HashParam_H_SHA512),                               \
            (HashH == 16 ?                                              \
             SPHINCS_HashParam_T_SHA256 :                               \
             SPHINCS_HashParam_T_SHA512)                                \
            ), }

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
