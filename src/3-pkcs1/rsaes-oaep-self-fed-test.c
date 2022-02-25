/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix RSAES_OAEP
#define SSLEN 16
#include "test-self-fed-defs.c.h"

#include "../3-pkc-test-utils/test-self-fed-kem.c.h"
