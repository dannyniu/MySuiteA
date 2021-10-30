/* DannyNiu/NJF, 2021-07-29. Public Domain. */

#include "rsa.h"
#include "../0-exec/struct-delta.c.h"

vlong_t *rsa_enc(RSA_Pub_Ctx_Hdr_t *restrict x)
{
    return vlong_modexpv(
        DeltaTo(x, offset_w2), // ciphertext output - C.
        DeltaTo(x, offset_w1), // plaintext input - M.
        DeltaTo(x, offset_e), // public exponent - e.
        DeltaTo(x, offset_w3), // tmp1.
        DeltaTo(x, offset_w4), // tmp2.
        (vlong_modfunc_t)vlong_remv_inplace,
        DeltaTo(x, offset_n));
}
