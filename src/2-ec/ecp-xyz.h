/* DannyNiu/NJF, 2021-12-26. Public Domain. */

#ifndef MySuiteA_ecc_ecp_xyz_h
#define MySuiteA_ecc_ecp_xyz_h 1

// 'ecp' stands for "Elliptic Curve of Prime order".
// it implements arithmetic common to curves of short Weierstrass form.

#include "../1-integers/vlong.h"

typedef struct {
    uint32_t offset_x, offset_y, offset_z;
} ecp_xyz_t; // Homogeneous Coordinate Prime-Order Elliptic-Curve Point.

typedef struct {
    uint32_t offset_r;
    uint32_t offset_s;
    uint32_t offset_t;
    uint32_t offset_u;
    uint32_t offset_v;
    uint32_t offset_w;
} ecp_opctx_t; // Working Variables for Point Adding and Doubling.

typedef struct {
    vlong_modfunc_t modfunc;
    vlong_t const *mod_ctx;
} ecp_imod_aux_t;

typedef struct {
    int16_t plen;
    int16_t h;
    int32_t a;
    vlong_t const *b;
    vlong_t const *p;
    vlong_t const *n;
    vlong_t const *Gx;
    vlong_t const *Gy;
    ecp_imod_aux_t const *imod_aux;
} ecp_curve_t;

// this function is modelled after ``vlong_imod_inplace''.
vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux);

// 2022-02-05: Based on
// "Complete addition formulas for prime order elliptic curves"
// by Joost Renes, Craig Costello, and Lejla Batina, Oct 2015.
ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    int32_t a,
    vlong_t const *restrict b,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux);

// Based on that from section 3.1. of RFC-6090.
ecp_xyz_t *ecp_point_dbl_fast(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    int32_t a,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux);

//
// helper functions.

void ecp_xyz_copy(
    ecp_xyz_t *restrict dst,
    ecp_xyz_t const *restrict src);

void ecp_xyz_inf(ecp_xyz_t *p);

// naive double-and-add.
ecp_xyz_t *ecp_point_scale_accumulate(
    ecp_xyz_t *restrict accum,
    ecp_xyz_t *restrict tmp1, // temporary variables are
    ecp_xyz_t *restrict tmp2, // allocated by the caller
    ecp_xyz_t const *restrict base,
    vlong_t const *restrict scalar,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve);

#define ECP_XYZ_T(l)                            \
    struct {                                    \
        ecp_xyz_t header;                       \
        VLONG_T(l) x;                           \
        VLONG_T(l) y;                           \
        VLONG_T(l) z;                           \
    }

#define ECP_OPCTX_T(l)                          \
    struct {                                    \
        ecp_opctx_t header;                     \
        VLONG_T(l) r;                           \
        VLONG_T(l) s;                           \
        VLONG_T(l) t;                           \
        VLONG_T(l) u;                           \
        VLONG_T(l) v;                           \
        VLONG_T(l) w;                           \
    }

#define ECP_XYZ_SIZE(l) (                                       \
        sizeof(ecp_xyz_t) +                                     \
        (sizeof(vlong_size_t) + sizeof(uint32_t) * (l)) * 3     \
        )

#define ECP_OPCTX_SIZE(l) (                                     \
        sizeof(ecp_opctx_t) +                                   \
        (sizeof(vlong_size_t) + sizeof(uint32_t) * (l)) * 6     \
        )

#define ECP_XYZ_INIT(type,l) ((type){                           \
            .header.offset_x = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 0,  \
            .header.offset_y = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 1,  \
            .header.offset_z = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 2,  \
            .x.c = l,                                           \
            .y.c = l,                                           \
            .z.c = l,                                           \
        })

#define ECP_OPCTX_INIT(type,l) ((type){                         \
            .header.offset_r = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 0,  \
            .header.offset_s = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 1,  \
            .header.offset_t = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 2,  \
            .header.offset_u = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 3,  \
            .header.offset_v = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 4,  \
            .header.offset_w = sizeof(ecp_opctx_t) +            \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 5,  \
            .r.c = l,                                           \
            .s.c = l,                                           \
            .t.c = l,                                           \
            .u.c = l,                                           \
            .v.c = l,                                           \
            .w.c = l,                                           \
        })

// 2 additional words for representation and computation overhead.
typedef ECP_XYZ_T(10) ecp256_xyz_t;
typedef ECP_XYZ_T(14) ecp384_xyz_t;

// the same overhead reason.
typedef ECP_OPCTX_T(10) ecp256_opctx_t;
typedef ECP_OPCTX_T(14) ecp384_opctx_t;

#define ECP256_XYZ_SIZE ECP_XYZ_SIZE(10)
#define ECP384_XYZ_SIZE ECP_XYZ_SIZE(14)

#define ECP256_OPCTX_SIZE ECP_OPCTX_SIZE(10)
#define ECP384_OPCTX_SIZE ECP_OPCTX_SIZE(14)

#define ECP256_XYZ_INIT ECP_XYZ_INIT(ecp256_xyz_t,10)
#define ECP384_XYZ_INIT ECP_XYZ_INIT(ecp384_xyz_t,14)

#define ECP256_OPCTX_INIT ECP_OPCTX_INIT(ecp256_opctx_t,10)
#define ECP384_OPCTX_INIT ECP_OPCTX_INIT(ecp384_opctx_t,14)

#endif /* MySuiteA_ecc_ecp_xyz_h */
