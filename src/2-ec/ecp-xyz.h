/* DannyNiu/NJF, 2021-12-26. Public Domain. */

#ifndef MySuiteA_ecc_ecp_xyz_h
#define MySuiteA_ecc_ecp_xyz_h 1

// 'ecp' stands for "Elliptic Curve of Prime order".
// it implements arithmetic common to curves of short Weierstrass form.

#include "ec-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 * 3       .
typedef struct {
    uint32_t offset_x, offset_y, offset_z;
} ecp_xyz_t; // Homogeneous Coordinate Prime-Order Elliptic-Curve Point.

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 * 6       .
typedef struct {
    uint32_t offset_r;
    uint32_t offset_s;
    uint32_t offset_t;
    uint32_t offset_u;
    uint32_t offset_v;
    uint32_t offset_w;
} ecp_opctx_t; // Working Variables for Point Adding and Doubling.

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4*4.5 | 4 * 7 | 8 * 6
typedef struct {
    uint16_t plen;
    int16_t h;
    int32_t a;
    vlong_t const *b;
    vlong_t const *p;
    vlong_t const *n;
    ecp_xyz_t const *G;
    ecp_imod_aux_t const *imod_aux;
} ecp_curve_t;

// 2022-02-05: Based on
// "Complete addition formulas for prime order elliptic curves"
// by Joost Renes, Craig Costello, and Lejla Batina, Oct 2015.
// available at: <https://eprint.iacr.org/2015/1060>
ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve);

// Based on that from section 3.1. of RFC-6090.
ecp_xyz_t *ecp_point_dbl_fast(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_opctx_t *restrict opctx,
    ecp_curve_t const *restrict curve);

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

// modular square root mod prime p with p === 3 mod 4.
vlong_t *vlong_sqrt_c3m4(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1, // temporary variables are
    vlong_t *restrict tmp2, // allocated by the caller
    const ecp_imod_aux_t *restrict aux);

// modular inversion over the finite field of the elliptic curve.
vlong_t *vlong_inv_mod_p_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecp_curve_t const *restrict curve);

// modular inversion over the order of the elliptic curve group.
vlong_t *vlong_inv_mod_n_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecp_curve_t const *restrict curve);

#define ECP_XYZ_T(bits)                         \
    struct {                                    \
        ecp_xyz_t header;                       \
        VLONG_T(VLONG_BITS_WCNT(bits)) x;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) y;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) z;       \
    }

#define ECP_OPCTX_T(bits)                       \
    struct {                                    \
        ecp_opctx_t header;                     \
        VLONG_T(VLONG_BITS_WCNT(bits)) r;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) s;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) t;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) u;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) v;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) w;       \
    }

#define ECP_XYZ_SIZE(bits) (                    \
        sizeof(ecp_xyz_t) +                     \
        VLONG_BITS_SIZE(bits) * 3               \
        )

#define ECP_OPCTX_SIZE(bits) (                  \
        sizeof(ecp_opctx_t) +                   \
        VLONG_BITS_SIZE(bits) * 6               \
        )

#define ECP_XYZ_HDR_INIT(bits)                  \
    ((ecp_xyz_t){                               \
        .offset_x = sizeof(ecp_xyz_t) +         \
        VLONG_BITS_SIZE(bits) * 0,              \
        .offset_y = sizeof(ecp_xyz_t) +         \
        VLONG_BITS_SIZE(bits) * 1,              \
        .offset_z = sizeof(ecp_xyz_t) +         \
        VLONG_BITS_SIZE(bits) * 2,              \
    })

#define ECP_XYZ_INIT(type,bits,...)             \
    ((type){                                    \
        .header = ECP_XYZ_HDR_INIT(bits),       \
        .x.c = VLONG_BITS_WCNT(bits),           \
        .y.c = VLONG_BITS_WCNT(bits),           \
        .z.c = VLONG_BITS_WCNT(bits),           \
        __VA_ARGS__                             \
    })

#define ECP_OPCTX_HDR_INIT(bits)                \
    ((ecp_opctx_t){                             \
        .offset_r = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 0,              \
        .offset_s = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 1,              \
        .offset_t = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 2,              \
        .offset_u = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 3,              \
        .offset_v = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 4,              \
        .offset_w = sizeof(ecp_opctx_t) +       \
        VLONG_BITS_SIZE(bits) * 5,              \
    })

#define ECP_OPCTX_INIT(type,bits)               \
    ((type){                                    \
        .header = ECP_OPCTX_HDR_INIT(bits),     \
        .r.c = VLONG_BITS_WCNT(bits),           \
        .s.c = VLONG_BITS_WCNT(bits),           \
        .t.c = VLONG_BITS_WCNT(bits),           \
        .u.c = VLONG_BITS_WCNT(bits),           \
        .v.c = VLONG_BITS_WCNT(bits),           \
        .w.c = VLONG_BITS_WCNT(bits),           \
    })

void  ecp_xyz_init(  ecp_xyz_t   *xyz, unsigned bits);
void ecp_opctx_init(ecp_opctx_t *opctx, unsigned bits);

typedef ECP_XYZ_T(256) ecp256_xyz_t;
typedef ECP_XYZ_T(384) ecp384_xyz_t;

typedef ECP_OPCTX_T(256) ecp256_opctx_t;
typedef ECP_OPCTX_T(384) ecp384_opctx_t;

#define ECP256_XYZ_SIZE ECP_XYZ_SIZE(256)
#define ECP384_XYZ_SIZE ECP_XYZ_SIZE(384)

#define ECP256_OPCTX_SIZE ECP_OPCTX_SIZE(256)
#define ECP384_OPCTX_SIZE ECP_OPCTX_SIZE(384)

#define ECP256_XYZ_INIT(...) ECP_XYZ_INIT(ecp256_xyz_t,256,__VA_ARGS__)
#define ECP384_XYZ_INIT(...) ECP_XYZ_INIT(ecp384_xyz_t,384,__VA_ARGS__)

#define ECP256_OPCTX_INIT ECP_OPCTX_INIT(ecp256_opctx_t,256)
#define ECP384_OPCTX_INIT ECP_OPCTX_INIT(ecp384_opctx_t,384)

enum {
    ptrCurveDef = qPrivateUseBegin + 1,
    bytesOpCtx = qPrivateUseBegin + 2,
    bytesECXYZ = qPrivateUseBegin + 3,
    bytesVLong = qPrivateUseBegin + 4,
};

#define c_Curve(q,bits) (                       \
        q==bytesOpCtx ? ECP_OPCTX_SIZE(bits) :  \
        q==bytesECXYZ ? ECP_XYZ_SIZE(bits) :    \
        q==bytesVLong ? VLONG_BITS_SIZE(bits) : \
        0)

#define x_Curve(q,bits,name_factory) (                  \
        q==ptrCurveDef ? (IntPtr)name_factory(bits) :   \
        c_Curve(q,bits) )

#define NameFactory_SECP_R(bits) secp##bits##r1

#endif /* MySuiteA_ecc_ecp_xyz_h */
