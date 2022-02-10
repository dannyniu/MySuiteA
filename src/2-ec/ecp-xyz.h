/* DannyNiu/NJF, 2021-12-26. Public Domain. */

#ifndef MySuiteA_ecc_ecp_xyz_h
#define MySuiteA_ecc_ecp_xyz_h 1

// 'ecp' stands for "Elliptic Curve of Prime order".
// it implements arithmetic common to curves of short Weierstrass form.

#include "../1-integers/vlong.h"

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
// align spec: 2 * 2 | 4 * 2 | 8 * 2
typedef struct {
    vlong_modfunc_t modfunc;
    vlong_t const *mod_ctx;
} ecp_imod_aux_t;

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

// this function is modelled after ``vlong_imod_inplace''.
vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux);

// 2022-02-05: Based on
// "Complete addition formulas for prime order elliptic curves"
// by Joost Renes, Craig Costello, and Lejla Batina, Oct 2015.
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
    ecp_curve_t *restrict curve);

// modular inversion over the order of the elliptic curve group.
vlong_t *vlong_inv_mod_n_fermat(
    vlong_t *restrict out,
    vlong_t const *x,
    vlong_t *restrict tmp1,
    vlong_t *restrict tmp2,
    ecp_curve_t *restrict curve);

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

#define ECP_XYZ_INIT(type,l,...) ((type){                       \
            .header.offset_x = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 0,  \
            .header.offset_y = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 1,  \
            .header.offset_z = sizeof(ecp_xyz_t) +              \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 2,  \
            .x.c = l,                                           \
            .y.c = l,                                           \
            .z.c = l,                                           \
            __VA_ARGS__                                         \
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

#define ECP256_XYZ_INIT(...) ECP_XYZ_INIT(ecp256_xyz_t,10,__VA_ARGS__)
#define ECP384_XYZ_INIT(...) ECP_XYZ_INIT(ecp384_xyz_t,14,__VA_ARGS__)

#define ECP256_OPCTX_INIT ECP_OPCTX_INIT(ecp256_opctx_t,10)
#define ECP384_OPCTX_INIT ECP_OPCTX_INIT(ecp384_opctx_t,14)

enum {
    ptrCurveDef = 20001,
    bytesOpCtx = 20002,
    bytesECXYZ = 20003,
};

#define c_Curve(q,bits) (                                       \
        q==bytesOpCtx ? ECP_OPCTX_SIZE((bits + 95) / 32) :      \
        q==bytesECXYZ ? ECP_XYZ_SIZE((bits + 95) / 32) :        \
        0)

#define x_Curve(q,bits,name_factory) (                  \
        q==ptrCurveDef ? (IntPtr)name_factory(bits) :   \
        c_Curve(q,bits) )

#define NameFactory_SECP_R(bits) secp##bits##r1

#endif /* MySuiteA_ecc_ecp_xyz_h */
