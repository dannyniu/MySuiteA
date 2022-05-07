/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsassa-pkcs1-v1_5.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSAEncryptionWithHash_CtCodec
#define MSGMAX 96
#include "test-api-defs.c.h"

#include "../3-pkc-test-utils/test-api-dss.c.h"
