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

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4 * 6 | 4 * 8 | 8 * 6
typedef struct {
    uint32_t pbits;
    int16_t a;
    uint16_t c;
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

#define ECED_XYTZ_T(bits)                       \
    struct {                                    \
        ecEd_xytz_t header;                     \
        VLONG_T(VLONG_BITS_WCNT(bits)) x;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) y;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) t;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) z;       \
    }

#define ECED_OPCTX_T(bits)                      \
    struct {                                    \
        ecEd_opctx_t header;                    \
        VLONG_T(VLONG_BITS_WCNT(bits)) r;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) s;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) u;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) v;       \
        VLONG_T(VLONG_BITS_WCNT(bits)) w;       \
    }

#define ECED_XYTZ_SIZE(bits) (                  \
        sizeof(ecEd_xytz_t) +                   \
        VLONG_BITS_SIZE(bits) * 4               \
        )

#define ECED_OPCTX_SIZE(bits) (                 \
        sizeof(ecEd_opctx_t) +                  \
        VLONG_BITS_SIZE(bits) * 5               \
        )

#define ECED_XYTZ_HDR_INIT(bits)                \
    ((ecEd_xytz_t){                             \
        .offset_x = sizeof(ecEd_xytz_t) +       \
        VLONG_BITS_SIZE(bits) * 0,              \
        .offset_y = sizeof(ecEd_xytz_t) +       \
        VLONG_BITS_SIZE(bits) * 1,              \
        .offset_t = sizeof(ecEd_xytz_t) +       \
        VLONG_BITS_SIZE(bits) * 2,              \
        .offset_z = sizeof(ecEd_xytz_t) +       \
        VLONG_BITS_SIZE(bits) * 3,              \
    })

// embedded ECED_XYTZ_HDR_INIT into ECED_XYTZ_INIT
// in order to work around a bug in GCC 11.3.0 that
// produced the "initializer element is not constant" error.

#define ECED_XYTZ_INIT(type,bits,...)           \
    ((type){                                    \
        .header = {                             \
            .offset_x = sizeof(ecEd_xytz_t) +   \
            VLONG_BITS_SIZE(bits) * 0,          \
            .offset_y = sizeof(ecEd_xytz_t) +   \
            VLONG_BITS_SIZE(bits) * 1,          \
            .offset_t = sizeof(ecEd_xytz_t) +   \
            VLONG_BITS_SIZE(bits) * 2,          \
            .offset_z = sizeof(ecEd_xytz_t) +   \
            VLONG_BITS_SIZE(bits) * 3,          \
        },                                      \
        .x.c = VLONG_BITS_WCNT(bits),           \
        .y.c = VLONG_BITS_WCNT(bits),           \
        .t.c = VLONG_BITS_WCNT(bits),           \
        .z.c = VLONG_BITS_WCNT(bits),           \
        __VA_ARGS__                             \
    })

#define ECED_OPCTX_HDR_INIT(bits)               \
    ((ecEd_opctx_t){                            \
        .offset_r = sizeof(ecEd_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 0,              \
        .offset_s = sizeof(ecEd_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 1,              \
        .offset_u = sizeof(ecEd_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 2,              \
        .offset_v = sizeof(ecEd_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 3,              \
        .offset_w = sizeof(ecEd_opctx_t) +      \
        VLONG_BITS_SIZE(bits) * 4,              \
    })

#define ECED_OPCTX_INIT(type,bits)              \
    ((type){                                    \
        .header = ECED_OPCTX_HDR_INIT(bits),    \
        .r.c = VLONG_BITS_WCNT(bits),           \
        .s.c = VLONG_BITS_WCNT(bits),           \
        .u.c = VLONG_BITS_WCNT(bits),           \
        .v.c = VLONG_BITS_WCNT(bits),           \
        .w.c = VLONG_BITS_WCNT(bits),           \
    })

void ecEd_xytz_init( ecEd_xytz_t  *xytz, unsigned bits);
void ecEd_opctx_init(ecEd_opctx_t *opctx, unsigned bits);

typedef ECED_XYTZ_T(256) ecEd256_xytz_t;
typedef ECED_XYTZ_T(448) ecEd448_xytz_t;

typedef ECED_OPCTX_T(256) ecEd256_opctx_t;
typedef ECED_OPCTX_T(448) ecEd448_opctx_t;

#define ECED256_XYTZ_SIZE ECED_XYTZ_SIZE(256)
#define ECED448_XYTZ_SIZE ECED_XYTZ_SIZE(448)

#define ECED256_OPCTX_SIZE ECED_OPCTX_SIZE(256)
#define ECED448_OPCTX_SIZE ECED_OPCTX_SIZE(448)

#define ECED256_XYTZ_INIT(...) ECED_XYTZ_INIT(ecEd256_xytz_t,256,__VA_ARGS__)
#define ECED448_XYTZ_INIT(...) ECED_XYTZ_INIT(ecEd448_xytz_t,448,__VA_ARGS__)

#define ECED256_OPCTX_INIT ECED_OPCTX_INIT(ecEd256_opctx_t,256)
#define ECED448_OPCTX_INIT ECED_OPCTX_INIT(ecEd448_opctx_t,448)

enum {
    ecEd_PtrCurveDef = qPrivateUseBegin + 1,
    ecEd_BytesOpCtx = qPrivateUseBegin + 2,
    ecEd_BytesXYTZ = qPrivateUseBegin + 3,
    ecEd_BytesVLong = qPrivateUseBegin + 4,
};

#define cCurveEd(q,bits) (                                      \
        q==ecEd_BytesOpCtx ? (IntPtr)ECED_OPCTX_SIZE(bits) :    \
        q==ecEd_BytesXYTZ ? (IntPtr)ECED_XYTZ_SIZE(bits) :      \
        q==ecEd_BytesVLong ? (IntPtr)VLONG_BITS_SIZE(bits) :    \
        0)

#define xCurveEd(q,bits,pCrvDef) (              \
        q==ecEd_PtrCurveDef ? (IntPtr)pCrvDef : \
        cCurveEd(q,bits) )

#endif /* MySuiteA_ecc_ecEd_h */
