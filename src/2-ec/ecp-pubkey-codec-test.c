/* DannyNiu/NJF, 2022-02-24. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecp-pubkey-codec.h"
#include "curves-secp.h"
#include "../0-exec/struct-delta.c.h"

uint8_t os[256];
ecp384_xyz_t Q, R, T1, T2;
ecp384_opctx_t opctx;
const ecp_curve_t *curve;

int fails = 0;

const ecp256_xyz_t R_256 = ECP256_XYZ_INIT(
    .x.v[7] = 0x2B42F576,
    .x.v[6] = 0xD07F4165,
    .x.v[5] = 0xFF65D1F3,
    .x.v[4] = 0xB1500F81,
    .x.v[3] = 0xE44C316F,
    .x.v[2] = 0x1F0B3EF5,
    .x.v[1] = 0x7325B69A,
    .x.v[0] = 0xCA46104F,

    .y.v[7] = 0x3CE76603,
    .y.v[6] = 0x264661EA,
    .y.v[5] = 0x2F602DF7,
    .y.v[4] = 0xB4510BBC,
    .y.v[3] = 0x9ED93923,
    .y.v[2] = 0x3C553EA5,
    .y.v[1] = 0xF42FB3F1,
    .y.v[0] = 0x338174B5,

    .z.v[0] = 1,
    );

const ecp384_xyz_t R_384 = ECP384_XYZ_INIT(
    .x.v[11] = 0x30EA514F,
    .x.v[10] = 0xC0D38D82,
    .x.v[ 9] = 0x08756F06,
    .x.v[ 8] = 0x8113C7CA,
    .x.v[ 7] = 0xDA9F66A3,
    .x.v[ 6] = 0xB40EA3B3,
    .x.v[ 5] = 0x13D040D9,
    .x.v[ 4] = 0xB57DD41A,
    .x.v[ 3] = 0x332795D0,
    .x.v[ 2] = 0x2CC7D507,
    .x.v[ 1] = 0xFCEF9FAF,
    .x.v[ 0] = 0x01A27088,

    .y.v[11] = 0xC04E3246,
    .y.v[10] = 0x5D14C50C,
    .y.v[ 9] = 0xBC3BCB88,
    .y.v[ 8] = 0xEA20F95B,
    .y.v[ 7] = 0x10616663,
    .y.v[ 6] = 0xFC62A8DC,
    .y.v[ 5] = 0xDB48D300,
    .y.v[ 4] = 0x6327EA7C,
    .y.v[ 3] = 0xA104F6F9,
    .y.v[ 2] = 0x294C66EA,
    .y.v[ 1] = 0x2487BD50,
    .y.v[ 0] = 0x357010C6,

    .z.v[0] = 1,
    );

#define vlong_cmpv(a, b) vlong_cmpv_shifted(a, b, 0)

void test_1point_1format(
    char const *testname,
    ecp_xyz_t const *restrict Q_in,
    size_t enclen)
{
    void *ret;
    ecp_xyz_t *Q_ptr = (void *)&Q;

    ret = ecp_point_encode(Q_in, os, enclen, curve);
    if( !ret )
    {
        printf("%s: encoding failed!\n", testname);
        fails++;
    }

    ret = ecp_point_decode(
        Q_ptr, os, enclen, (void *)&R, (void *)&T1, (void *)&T2,
        (ecp_opctx_t *)&opctx, curve);
    if( !ret )
    {
    for(size_t i=0; i<enclen; i++) printf("%02x", os[i]); printf("\n");
        printf("%s: decoding failed!\n", testname);
        fails++;
    }

    if( vlong_cmpv(DeltaTo(Q_ptr, offset_x), DeltaTo(Q_in, offset_x)) ||
        vlong_cmpv(DeltaTo(Q_ptr, offset_y), DeltaTo(Q_in, offset_y)) ||
        vlong_cmpv(DeltaTo(Q_ptr, offset_z), DeltaTo(Q_in, offset_z)) )
    {
        printf("%s: transcoding mismatch!\n", testname);
        fails++;
    }
}

void test_1point(
    char const *testname,
    ecp_xyz_t const *restrict Q_in)
{
    char test_sprintf[128];

    sprintf(test_sprintf, "%s: compressed", testname);
    test_1point_1format(test_sprintf, Q_in, 1+curve->plen);

    sprintf(test_sprintf, "%s: uncompressed", testname);
    test_1point_1format(test_sprintf, Q_in, 1+curve->plen*2);
}

void test_1param(
    char const *testname,
    ecp_xyz_t const *restrict Q_in)
{
    char test_sprintf[128];

    sprintf(test_sprintf, "%s: base point", testname);
    test_1point(test_sprintf, (void const *)curve->G);

    sprintf(test_sprintf, "%s: random point", testname);
    test_1point(test_sprintf, Q_in);
}

int main(void)
{
    *(ecp256_xyz_t *)&Q = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&R = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&T1 = ECP256_XYZ_INIT();
    *(ecp256_xyz_t *)&T2 = ECP256_XYZ_INIT();
    *(ecp256_opctx_t *)&opctx = ECP256_OPCTX_INIT;
    curve = secp256r1;
    test_1param("P-256", (void const *)&R_256);

    *(ecp384_xyz_t *)&Q = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&R = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&T1 = ECP384_XYZ_INIT();
    *(ecp384_xyz_t *)&T2 = ECP384_XYZ_INIT();
    *(ecp384_opctx_t *)&opctx = ECP384_OPCTX_INIT;
    curve = secp384r1;
    test_1param("P-384", (void const *)&R_384);

    if( fails > 0 )
        return EXIT_FAILURE;
    else return EXIT_SUCCESS;
}
