/* DannyNiu/NJF, 2021-12-24. Public Domain. */

#include "rsassa-pss.h"

IntPtr tRSASSA_PSS(const CryptoParam_t *P, int q)
{
    return xRSASSA_PSS(
        (P ? P[0].info : NULL),
        (P ? P[1].info : NULL),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 0),
        (P ? P[4].aux : 0),
        q);
}

IntPtr iRSASSA_PSS_CtCodec(int q) { return xRSASSA_PSS_CtCodec(q); }
