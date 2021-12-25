/* DannyNiu/NJF, 2021-12-24. Public Domain. */

#include "rsaes-oaep.h"

IntPtr tRSAES_OAEP(const CryptoParam_t *P, int q)
{
    return xRSAES_OAEP(
        (P ? P[0].info : NULL),
        (P ? P[1].info : NULL),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 0),
        (P ? P[4].aux : 0),
        q);
}

IntPtr iRSAES_OAEP_CtCodec(int q) { return xRSAES_OAEP_CtCodec(q); }
