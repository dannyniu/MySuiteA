/* DannyNiu/NJF, 2020-12-25. Public Domain. */

#ifndef MySuiteA_vlong_h
#define MySuiteA_vlong_h 1

// V-Long stands for "Vector of ``long''s", or "Very Long".

#include "../mysuitea-common.h"

// vlong_size_t must be unsigned, as some code in the implementation
// depends on the wrap-around on underflow behavior.
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

// MARK: == Generic Division ==

vlong_t *vlong_divv( // returns ``rem''. 
    vlong_t *restrict rem,
    vlong_t *restrict quo,
    vlong_t const *a,
    vlong_t const *b);

vlong_t *vlong_remv_inplace(vlong_t *rem, vlong_t const *b);

// MARK: == Multiplicative Expressions ==

typedef void *(*vlong_modfunc_t)(
    vlong_t *restrict v,
    void *restrict ctx);

vlong_t *vlong_mulv(
    vlong_t *restrict out,
    vlong_t const *a,
    vlong_t const *b,
    vlong_modfunc_t modfunc,
    void *restrict mod_ctx);

#endif /* MySuiteA_vlong_h */
