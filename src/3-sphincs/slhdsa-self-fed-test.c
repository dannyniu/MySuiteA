/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"
#include "sphincs-hash-params-family-shake.h"
//#include "../2-hash/sha.h"

#define PKC_Algo_Prefix SLHDSA
#define MSGMAX 96

#define PKC_Keygen SLHDSA_Keygen

#define PKC_Encode_PrivateKey SLHDSA_Encode_PrivateKey
#define PKC_Decode_PrivateKey SLHDSA_Decode_PrivateKey
#define PKC_Export_PublicKey SLHDSA_Export_PublicKey
#define PKC_Encode_PublicKey SLHDSA_Encode_PublicKey
#define PKC_Decode_PublicKey SLHDSA_Decode_PublicKey

#define HashSubX(name,algo) SPHINCS_HashParam_##name##_##algo
#define HashSub(name,algo) (SPHINCS_HashParam_t)HashSubX(name,algo)

SLHDSA_Param_t params = {
    [0] = { .info = NULL, .aux = HashN, },
    [1] = { .info = NULL, .aux = HashH, },
    [2] = { .info = NULL, .aux = (IntPtr)HashSub(Hmsg, LongHash), },
    [3] = { .info = NULL, .aux = (IntPtr)HashSub(PRF, ShortHash), },
    [4] = { .info = NULL, .aux = (IntPtr)HashSub(PRFmsg, LongHash), },
    [5] = { .info = NULL, .aux = (IntPtr)HashSub(F, ShortHash), },
    [6] = { .info = NULL, .aux = (IntPtr)HashSub(H, LongHash), },
    [7] = { .info = NULL, .aux = (IntPtr)HashSub(T, LongHash), },
#if PKC_DSS_No_Incremental_Tests
    [8] = { .info = iCryptoObj_Null, .aux = 0, },
#else /* -- pre-hashing -- */
    [8] = { .info = glue(i,LongHash), .aux = 0, },
#endif /* PKC_DSS_No_Incremental_Tests */
};

#if PKC_DSS_No_Incremental_Tests

#define kgx_decl SLHDSA_CTX_T(HashN, HashH, CRYPTO_OBJ_NULL)
#define enx_decl SLHDSA_CTX_T(HashN, HashH, CRYPTO_OBJ_NULL)

#define kgx_init {                              \
        .header = SLHDSA_CTX_INIT(              \
            HashN, HashH,                       \
            HashSub(Hmsg, LongHash),            \
            HashSub(PRF, ShortHash),            \
            HashSub(PRFmsg, LongHash),          \
            HashSub(F, ShortHash),              \
            HashSub(H, LongHash),               \
            HashSub(T, LongHash),               \
            CRYPTO_OBJ_NULL                     \
            ), }

#define enx_init {                              \
        .header = SLHDSA_CTX_INIT(              \
            HashN, HashH,                       \
            HashSub(Hmsg, LongHash),            \
            HashSub(PRF, ShortHash),            \
            HashSub(PRFmsg, LongHash),          \
            HashSub(F, ShortHash),              \
            HashSub(H, LongHash),               \
            HashSub(T, LongHash),               \
            CRYPTO_OBJ_NULL                     \
            ), }

#else /* -- pre-hashing -- */

#define kgx_decl SLHDSA_CTX_T(HashN, HashH, glue(c,LongHash))
#define enx_decl SLHDSA_CTX_T(HashN, HashH, glue(c,LongHash))

#define kgx_init {                              \
        .header = SLHDSA_CTX_INIT(              \
            HashN, HashH,                       \
            HashSub(Hmsg, LongHash),            \
            HashSub(PRF, ShortHash),            \
            HashSub(PRFmsg, LongHash),          \
            HashSub(F, ShortHash),              \
            HashSub(H, LongHash),               \
            HashSub(T, LongHash),               \
            glue(x,LongHash)                    \
            ), }

#define enx_init {                              \
        .header = SLHDSA_CTX_INIT(              \
            HashN, HashH,                       \
            HashSub(Hmsg, LongHash),            \
            HashSub(PRF, ShortHash),            \
            HashSub(PRFmsg, LongHash),          \
            HashSub(F, ShortHash),              \
            HashSub(H, LongHash),               \
            HashSub(T, LongHash),               \
            glue(x,LongHash)                    \
            ), }

#endif /* PKC_DSS_No_Incremental_Tests */

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
