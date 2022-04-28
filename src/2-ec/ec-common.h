/* DannyNiu/NJF, 2022-04-27. Public Domain. */

#ifndef MySuiteA_ecc_ec_common_h
#define MySuiteA_ecc_ec_common_h 1

#include "../1-integers/vlong.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 2 * 2 | 4 * 2 | 8 * 2
typedef struct {
    vlong_modfunc_t modfunc;
    vlong_t const *mod_ctx;
} ecp_imod_aux_t;

// this function is modelled after ``vlong_imod_inplace''.
vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux);

// This function is used to implement various algorithms that're based on
// modular exponentiation, such as modular square root over a prime mod p
// such that p === 3 mod 4, and modular inversion mod a prime.
vlong_t *vlong_modexpv_shiftadded(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    vlong_modfunc_t modfunc,
    vlong_t const *mod_ctx,
    int32_t addend, // should be small.
    short shift); // it's assumed that shift is (much) less than 32 bits.

#endif /* MySuiteA_ecc_ec_common_h */
