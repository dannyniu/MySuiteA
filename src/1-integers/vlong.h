/* DannyNiu/NJF, 2020-12-25. Public Domain. */

#ifndef MySuiteA_vlong_h
#define MySuiteA_vlong_h 1

// V-Long stands for "Vector of ``long''s", or "Very Long".

#include "../mysuitea-common.h"

// ``vlong_size_t'' must be unsigned, as some code in the implementation
// depends on the wrap-around on underflow behavior.
//
// An awkard situation is that, ``vlong_size_t'' must also be 32-bit
// to make sure the alignment rules won't induce any "hole" in
// consecutive ``vlong_t'' data structures.
//
typedef uint32_t vlong_size_t;

#define VLONG_T(...) struct { vlong_size_t c; uint32_t v[__VA_ARGS__]; }
#define VLONG_INIT(cnt) { .c = cnt }

typedef VLONG_T() vlong_t;

// ``vlong_*'' functions return NULL when the parameters of
// operands are invalid (e.g. lack space to hold full values).

// MARK: == Additive Expressions ==

// These are intentionally not restrict-qualified.
vlong_t *vlong_adds(
    vlong_t *out,
    vlong_t const *a,
    int64_t b, vlong_size_t s); // -UINT32_MAX <= b <= UINT32_MAX

vlong_t *vlong_addv(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b);

vlong_t *vlong_subv(
    vlong_t *out,
    vlong_t const *a,
    vlong_t const *b);

// MARK: == Scalar Multiplication Expressions ==

// These are intentially not restrict-qualified.
vlong_t *vlong_mulx(vlong_t *out, vlong_t const *a);
vlong_t *vlong_muls(vlong_t *out, vlong_t const *a, uint32_t b, int accum);

// Returns
// - 0 if a == b,
// - 1 if a > b, and
// - 2 if a < b.
int vlong_cmps(uint32_t a, uint32_t b);

// MARK: == Generic Division ==

vlong_t *vlong_divv( // returns ``rem''. 
    vlong_t *restrict rem,
    vlong_t *restrict quo,
    vlong_t const *a,
    vlong_t const *b);

// calculate rem (mod p) treating both as unsigned integers.
vlong_t *vlong_remv_inplace(vlong_t *rem, const vlong_t *b);

// calculate rem (mod p) treating rem as 2's complement signed integer
// with the (soft) restriction that rem must be longer than b.
vlong_t *vlong_imod_inplace(vlong_t *rem, const vlong_t *b);

// MARK: == Multiplicative Expressions ==

typedef void *(*vlong_modfunc_t)(
    vlong_t *restrict v,
    const void *restrict ctx);

// Multiply ``a'' and ``b'' and store the result into ``out''.
// - ``mask'' shall be either 1 or 0, and is
//   equivalent to an exponent for ``b''.
//   All other values cause undefined behavior.
// - the multiplication is optionally modular if ``modfunc''
//   (and optionally ``mod_ctx'' if needed) is specified.
vlong_t *vlong_mulv_masked(
    vlong_t *restrict out,
    vlong_t const *a,
    vlong_t const *b,
    uint32_t mask,
    vlong_modfunc_t modfunc,
    const void *restrict mod_ctx);

// MAKR: == Modular Exponentiation ==

// 2021-06-06:
// There was an attempted optimization to reduce the number of
// temporary variables by 1. While the attempt was successful,
// it resulted in a break of assumption made by codes elsewhere.
//
// Specifically, it broke the assumption that:
// 1. the number pointed to by ``base'' won't be modified, and
// 2. ``out'' is not aliased to other numbers by intention and
//    is modifiable.
//
// These assumptions are actually indicated through the use of
// appropriate qualifiers on types.
vlong_t *vlong_modexpv(
    vlong_t *restrict out,
    vlong_t const *base,
    vlong_t const *e,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    vlong_modfunc_t modfunc,
    const void *restrict mod_ctx);

#endif /* MySuiteA_vlong_h */
