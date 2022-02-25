/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pss.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSASSA_PSS_CtCodec
#define MSGMAX 96
#include "test-api-defs.c.h"

#include "../3-pkc-test-utils/test-api-dss.c.h"
