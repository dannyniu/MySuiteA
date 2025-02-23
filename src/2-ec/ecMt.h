/* DannyNiu/NJF, 2022-04-24. Public Domain. */

#ifndef MySuiteA_ecc_ecMt_h
#define MySuiteA_ecc_ecMt_h 1

// ecMt stands for "Elliptic Curve of Montgomery form"

#include "ec-common.h"

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec:         4 *12
typedef struct {
    uint32_t offset_x2, offset_z2;
    uint32_t offset_x3, offset_z3;
    uint32_t offset_da, offset_cb, offset_tmp;
    uint32_t offset_a, offset_b, offset_c, offset_d, offset_e;
} ecMt_opctx_t;

vlong_t *ecMt_point_scale(
    vlong_t const *restrict k,
    vlong_t *restrict x1,
    uint32_t a24, // (a - 2) / 4.
    vlong_size_t bits,
    ecMt_opctx_t *restrict opctx,
    ecp_imod_aux_t const *restrict imod_aux);

#define ECMT_OPCTX_T(bits)                      \
    struct {                                    \
        ecMt_opctx_t header;                    \
        VLONG_T(VLONG_BITS_WCNT(bits)) x2;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) z2;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) x3;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) z3;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) da;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) cb;      \
        VLONG_T(VLONG_BITS_WCNT(bits)) tmp;     \
        VLONG_T(VLONG_BITS_WCNT(bits)) a;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) b;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) c;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) d;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) e;       \
    }

#define ECMT_OPCTX_SIZE(bits) (                 \
        sizeof(ecMt_opctx_t) +                  \
        VLONG_BITS_SIZE(bits) * 12              \
        )

#define ECMT_OPCTX_HDR_INIT(bits)               \
    ((ecMt_opctx_t){                            \
        .offset_x2 = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 0,              \
        .offset_z2 = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 1,              \
        .offset_x3 = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 2,              \
        .offset_z3 = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 3,              \
        .offset_da = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 4,              \
        .offset_cb = sizeof(ecMt_opctx_t) +     \
        VLONG_BITS_SIZE(bits) * 5,              \
        .offset_tmp = sizeof(ecMt_opctx_t) +    \
        VLONG_BITS_SIZE(bits) * 6,              \
        .offset_a = sizeof(ecMt_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 7,              \
        .offset_b = sizeof(ecMt_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 8,              \
        .offset_c = sizeof(ecMt_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 9,              \
        .offset_d = sizeof(ecMt_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 10,             \
        .offset_e = sizeof(ecMt_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 11,             \
    })

// 2022-12-30, there was a type: ECMT_OPCTX_ININT.
#define ECMT_OPCTX_INIT(type,bits)              \
    ((type){                                    \
        .header = ECMT_OPCTX_HDR_INIT(bits),    \
        .x2.c = VLONG_BITS_WCNT(bits),          \
        .z2.c = VLONG_BITS_WCNT(bits),          \
        .x3.c = VLONG_BITS_WCNT(bits),          \
        .z3.c = VLONG_BITS_WCNT(bits),          \
        .da.c = VLONG_BITS_WCNT(bits),          \
        .cb.c = VLONG_BITS_WCNT(bits),          \
        .tmp.c = VLONG_BITS_WCNT(bits),         \
        .a.c = VLONG_BITS_WCNT(bits),           \
        .b.c = VLONG_BITS_WCNT(bits),           \
        .c.c = VLONG_BITS_WCNT(bits),           \
        .d.c = VLONG_BITS_WCNT(bits),           \
        .e.c = VLONG_BITS_WCNT(bits),           \
    })

void ecMt_opctx_init(ecMt_opctx_t *opctx, unsigned bits);

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 5 | 4 * 6 | 8 * 4
typedef struct {
    uint32_t pbits;
    int32_t a;
    uint32_t u_p;
    uint32_t sslen;

    void (*gen_scl)(
        vlong_t *restrict k,
        vlong_t *restrict K,
        ecMt_opctx_t *restrict opctx,
        ecp_imod_aux_t const *restrict imod_aux,
        GenFunc_t prng_gen, void *restrict prng);

    ecp_imod_aux_t const *modp;
} ecMt_curve_t;

enum {
    ecMt_PtrCurveDef = qPrivateUseBegin + 1,
    ecMt_BitsModulus = qPrivateUseBegin + 2,
};

#endif /* MySuiteA_ecc_ecMt_h */
