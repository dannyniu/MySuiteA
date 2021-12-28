/* DannyNiu/NJF, 2021-12-26. Public Domain. */

#ifndef MySuiteA_ecc_secp_xyz_h
#define MySuiteA_ecc_secp_xyz_h 1

#include "../1-integers/vlong.h"

typedef struct {
    uint32_t offset_x, offset_y, offset_z;
} secp_xyz_t; // Homogeneous Coordinate Prime-Order Elliptic-Curve Point.

typedef struct {
    uint32_t offset_s;
    uint32_t offset_t;
    uint32_t offset_u;
    uint32_t offset_v;
} secp_opctx_t; // Working Variables for Point Adding and Doubling.

typedef struct {
    vlong_modfunc_t modfunc;
    vlong_t const *mod_ctx;
} sec_Fp_imod_aux_t;

extern const sec_Fp_imod_aux_t *secp256r1_imod_aux;
extern const sec_Fp_imod_aux_t *secp384r1_imod_aux;

// this function is modelled after ``vlong_imod_inplace''.
vlong_t *sec_Fp_imod_inplace(vlong_t *rem, const sec_Fp_imod_aux_t *aux);

//
// SEC#1 Prime-Order Elliptic Curve Point Arithmetics.

secp_xyz_t *secp_point_add(
    secp_xyz_t *out,
    secp_xyz_t const *p1,
    secp_xyz_t const *p2,
    secp_opctx_t *ctx,
    const sec_Fp_imod_aux_t *aux);

secp_xyz_t *secp_point_dbl(
    secp_xyz_t *out,
    secp_xyz_t const *p1,
    int32_t a,
    secp_opctx_t *ctx,
    const sec_Fp_imod_aux_t *aux);

typedef struct {
    secp_xyz_t header;
    VLONG_T(10) x;
    VLONG_T(10) y;
    VLONG_T(10) z;
} secp256_xyz_t; // for both random and Koblitz curves.

typedef struct {
    secp_xyz_t header;
    VLONG_T(14) x;
    VLONG_T(14) y;
    VLONG_T(14) z;
} secp384_xyz_t; // even though no Koblitz curve defined for 384-bit fields.

typedef struct {
    secp_opctx_t header;
    VLONG_T(10) s;
    VLONG_T(10) t;
    VLONG_T(10) u;
    VLONG_T(10) v;
} secp256_opctx_t;

typedef struct {
    secp_opctx_t header;
    VLONG_T(14) s;
    VLONG_T(14) t;
    VLONG_T(14) u;
    VLONG_T(14) v;
} secp384_opctx_t;

#define SECP_XYZ_INIT(type,l) ((type){                          \
            .header.offset_x = sizeof(secp_xyz_t) +             \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 0,  \
            .header.offset_y = sizeof(secp_xyz_t) +             \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 1,  \
            .header.offset_z = sizeof(secp_xyz_t) +             \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 2,  \
            .x.c = l,                                           \
            .y.c = l,                                           \
            .z.c = l,                                           \
        })

#define SECP256_XYZ_INIT SECP_XYZ_INIT(secp256_xyz_t,10)
#define SECP384_XYZ_INIT SECP_XYZ_INIT(secp384_xyz_t,14)

#define SECP_OPCTX_INIT(type,l) ((type){                        \
            .header.offset_s = sizeof(secp_opctx_t) +           \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 0,  \
            .header.offset_t = sizeof(secp_opctx_t) +           \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 1,  \
            .header.offset_u = sizeof(secp_opctx_t) +           \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 2,  \
            .header.offset_v = sizeof(secp_opctx_t) +           \
            (sizeof(vlong_size_t) + sizeof(uint32_t) * l) * 3,  \
            .s.c = l,                                           \
            .t.c = l,                                           \
            .u.c = l,                                           \
            .v.c = l,                                           \
        })

#define SECP256_OPCTX_INIT SECP_OPCTX_INIT(secp256_opctx_t,10)
#define SECP384_OPCTX_INIT SECP_OPCTX_INIT(secp384_opctx_t,14)

#endif /* MySuiteA_ecc_secp_xyz_h */
