/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"
#include "sphincs-hash-params-family-shake.h"

#define PKC_InstAlgo tSLHDSA
#define PKC_CtAlgo iSLHDSA_CtCodec
#define PKC_KeyAlgo iSLHDSA_KeyCodec
#define MSGMAX 96

#define HashSubX(name,algo) SPHINCS_HashParam_##name##_##algo
#define HashSub(name,algo) (IntPtr)HashSubX(name,algo)

SLHDSA_Param_t params = {
    [0] = { .info = NULL, .aux = HashN, },
    [1] = { .info = NULL, .aux = HashH, },
    [2] = { .info = NULL, .aux = HashSub(Hmsg, LongHash), },
    [3] = { .info = NULL, .aux = HashSub(PRF, ShortHash), },
    [4] = { .info = NULL, .aux = HashSub(PRFmsg, LongHash), },
    [5] = { .info = NULL, .aux = HashSub(F, ShortHash), },
    [6] = { .info = NULL, .aux = HashSub(H, LongHash), },
    [7] = { .info = NULL, .aux = HashSub(T, LongHash), },
#if PKC_DSS_No_Incremental_Tests
    [8] = { .info = iCryptoObj_Null, .aux = 0, },
#else /* -- pre-hashing -- */
    [8] = { .info = glue(i,LongHash), .aux = 0, },
#endif /* PKC_DSS_No_Incremental_Tests */
};

#include "../3-pkc-test-utils/test-api-dss.c.h"
