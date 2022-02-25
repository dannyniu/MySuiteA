/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSAES_OAEP_CtCodec
#define SSLEN 16
#include "test-api-defs.c.h"

#include "../3-pkc-test-utils/test-api-kem.c.h"
