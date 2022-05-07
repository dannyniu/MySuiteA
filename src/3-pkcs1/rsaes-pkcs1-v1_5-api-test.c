/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsaes-pkcs1-v1_5.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSAEncryption_CtCodec
#define SSLEN 16
#include "test-api-defs.c.h"

#include "../3-pkc-test-utils/test-api-kem.c.h"
