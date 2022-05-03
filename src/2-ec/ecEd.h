/* DannyNiu/NJF, 2022-05-02. Public Domain. */

#ifndef MySuiteA_ecc_ecEd_h
#define MySuiteA_ecc_ecEd_h 1

// ecEd stands for "Elliptic Curve of Edwards forms".

#include "ec-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 * 4       .
typedef struct {
    uint32_t offset_x, offset_y, offset_t, offset_z;
} ecEd_xytz_t;

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 * 5       .
typedef struct {
    uint32_t offset_r;
    uint32_t offset_s;
    uint32_t offset_u;
    uint32_t offset_v;
    uint32_t offset_w;
} ecEd_opctx_t;

typedef struct {
    uint32_t pbits;
    int32_t a;
    int32_t d_over; // by convention, d_over follows the sign of the
    int32_t d_under; // fraction, where as d_under is always positive.
    vlong_t const *p;
    vlong_t const *L;
    ecEd_xytz_t const *B;
    ecp_imod_aux_t const *imod_aux;
} ecEd_curve_t;

// 2022-05-02: Based on
// "Twisted Edwards Curves Revisited"
// by Huseyin Hisil, Kenneth Koon-Ho Wong,
// Gary Carter, and Ed Dawson, Dec 2008.
// available at: <https://eprint.iacr.org/2008/522>
ecEd_xytz_t *ecEd_point_add(
    ecEd_xytz_t *out, // intentionally not restrict-qualified,
    ecEd_xytz_t const *p1,
    ecEd_xytz_t const *p2,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve);

ecEd_xytz_t *ecEd_point_dbl(
    ecEd_xytz_t *restrict out,
    ecEd_xytz_t const *p1,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve);

void ecEd_xytz_copy(
    ecEd_xytz_t *restrict dst,
    ecEd_xytz_t const *restrict src);

void ecEd_xytz_inf(ecEd_xytz_t *p);

ecEd_xytz_t *ecEd_point_scale_accumulate(
    ecEd_xytz_t *restrict accum,
    ecEd_xytz_t *restrict tmp1, // temporary variables are
    ecEd_xytz_t *restrict tmp2, // allocated by the caller
    ecEd_xytz_t const *restrict base,
    vlong_t const *restrict scalar,
    ecEd_opctx_t *restrict opctx,
    ecEd_curve_t const *restrict curve);

#endif /* MySuiteA_ecc_ecEd_h */
