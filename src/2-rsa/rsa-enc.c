/* DannyNiu/NJF, 2021-07-29. Public Domain. */

#include "rsa.h"

vlong_t *rsa_enc(RSA_Public_Context_t *restrict x)
{
    uint8_t *bp = (void *)x;
    
    return vlong_modexpv(
        (vlong_t *)(bp + x->offset_w2), // ciphertext output - C.
        (vlong_t *)(bp + x->offset_w1), // plaintext input - M.
        (vlong_t *)(bp + x->offset_e), // public exponent - e.
        (vlong_t *)(bp + x->offset_w3), // tmp1.
        (vlong_t *)(bp + x->offset_w4), // tmp2.
        (vlong_modfunc_t)vlong_remv_inplace,
        (void *)(bp + x->offset_n));
}
