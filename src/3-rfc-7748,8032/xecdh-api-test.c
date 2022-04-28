/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "x25519.h"
#include "x448.h"

#ifndef PKC_CtAlgo
#define PKC_CtAlgo iX25519_CtCodec
#endif /* PKC_CtAlgo */

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#ifndef PKC_KeyAlgo
#define PKC_KeyAlgo iX25519_KeyCodec
#endif /* PKC_KeyAlgo */

void *params = NULL;

#include "../3-pkc-test-utils/test-api-kem.c.h"
