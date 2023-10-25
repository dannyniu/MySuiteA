/* DannyNiu/NJF, 2023-10-25. Public Domain. */

#include "mlkem.h"

#define PKC_CtAlgo iMLKEM_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_KeyAlgo iMLKEM_KeyCodec

MLKEM_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
};

#include "../3-pkc-test-utils/test-api-kem.c.h"
