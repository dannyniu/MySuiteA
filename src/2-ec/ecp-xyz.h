/* DannyNiu/NJF, 2021-12-26. Public Domain. */

#ifndef MySuiteA_ecc_ecp_xyz_h
#define MySuiteA_ecc_ecp_xyz_h 1

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

extern const ecp_imod_aux_t *secp256r1_imod_aux;
extern const ecp_imod_aux_t *secp384r1_imod_aux;

// this function is modelled after ``vlong_imod_inplace''.
vlong_t *ecp_imod_inplace(vlong_t *rem, const ecp_imod_aux_t *aux);

//
// Short Weierstrass Prime-Order Elliptic Curve Point Arithmetics.

// 2022-02-05: Based on
// "Complete addition formulas for prime order elliptic curves"
// Joost Renes, Craig Costello, and Lejla Batina, Oct 2015.
ecp_xyz_t *ecp_point_add_rcb15(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    ecp_xyz_t const *p2,
    int32_t a,
    vlong_t *restrict b,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux);

// Based on that from section 3.1. of RFC-6090.
ecp_xyz_t *ecp_point_dbl_fast(
    ecp_xyz_t *restrict out,
    ecp_xyz_t const *p1,
    int32_t a,
    ecp_opctx_t *restrict ctx,
    const ecp_imod_aux_t *restrict aux);

typedef struct {
    ecp_xyz_t header;
    VLONG_T(10) x;
    VLONG_T(10) y;
    VLONG_T(10) z;
} ecp256_xyz_t; // for both random and Koblitz curves.

typedef struct {
    ecp_xyz_t header;
    VLONG_T(14) x;
    VLONG_T(14) y;
    VLONG_T(14) z;
} ecp384_xyz_t; // even though no Koblitz curve defined for 384-bit fields.

typedef struct {
    ecp_opctx_t header;
    VLONG_T(10) r;
    VLONG_T(10) s;
    VLONG_T(10) t;
    VLONG_T(10) u;
    VLONG_T(10) v;
    VLONG_T(10) w;
} ecp256_opctx_t;

typedef struct {
    ecp_opctx_t header;
    VLONG_T(14) r;
    VLONG_T(14) s;
    VLONG_T(14) t;
    VLONG_T(14) u;
    VLONG_T(14) v;
    VLONG_T(14) w;
} ecp384_opctx_t;

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

#define ECP256_XYZ_INIT ECP_XYZ_INIT(ecp256_xyz_t,10)
#define ECP384_XYZ_INIT ECP_XYZ_INIT(ecp384_xyz_t,14)

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

#define ECP256_OPCTX_INIT ECP_OPCTX_INIT(ecp256_opctx_t,10)
#define ECP384_OPCTX_INIT ECP_OPCTX_INIT(ecp384_opctx_t,14)

#endif /* MySuiteA_ecc_ecp_xyz_h */
