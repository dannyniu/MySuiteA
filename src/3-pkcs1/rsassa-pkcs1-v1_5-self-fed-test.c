/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pkcs1-v1_5.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix RSAEncryptionWithHash
#define MSGMAX 96
#include "test-self-fed-defs.c.h"

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
