/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "sm2sig.h"
#include "../2-ec/curveSM2.h"
#include "../2-hash/sm3.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"
#include "../test-utils.c.h"

typedef struct {
    ECC_Hash_Ctx_Hdr_t x_hdr;
    sm3_t hash;
    ecp384_opctx_t opctx;
    ecp384_xyz_t Points[4];
    VLONG_T(14) Scalars[2];
} SM2SIG_Ctx_t;

SM2SIG_Ctx_t sm2sigCtx, sm2sigSavedCtx;

typedef struct {
    char *k, *d, *r, *s, *msg;
    SM2SIG_Param_t params;
} SM2SIG_Test_Vector_t;

SM2SIG_Test_Vector_t testvecs[] =
{
    {
        .k = 
        "59276E27 D506861A 16680F3A D9C02DCC"
        "EF3CC1FA 3CDBE4CE 6D54B80D EAC1BC21",

        .d = 
        "3945208F 7B2144B1 3F36E38A C6D39F95"
        "88939369 2860B51A 42FB81EF 4DF7C5B8",

        .r =
        "F5A03B06 48D2C463 0EEAC513 E1BB81A1"
        "5944DA38 27D5B741 43AC7EAC EEE720B3",

        .s = 
        "B1B6AA29 DF212FD8 763182BC 0D421CA1"
        "BB9038FD 1F7F42D4 840B69C4 85BBC1AA",

        .msg = "message digest",

        .params[0].info = i_curveSM2,
        .params[1].info = iSM3,
        .params[0].aux = 0,
        .params[1].aux = 0,
    },
    
    {0},
};

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(void) // (int argc, char *argv[])
{
    ecp_opctx_t *opctx;
    uint8_t h1[64], h2[64];
    int fails = 0;

    SM2SIG_Test_Vector_t *testvec = testvecs;
    unsigned plen;

    while( testvec->msg )
    {
        plen = ((ecp_curve_t *)testvec->params[0].info(ptrCurveDef))->plen;
        plen = plen < 64 ? plen : 64;
        
        SM2SIG_Keygen(
            &sm2sigCtx.x_hdr, testvec->params,
            (GenFunc_t)FixedPRNG, testvec->d);

        SM2SIG_Sign(
            &sm2sigCtx.x_hdr,
            testvec->msg, strlen(testvec->msg),
            (GenFunc_t)FixedPRNG, testvec->k);

        opctx = DeltaTo((&sm2sigCtx.x_hdr), offset_opctx);

        vlong_I2OSP(DeltaTo(opctx, offset_r), h1, plen);
        FixedPRNG(testvec->r, h2, plen);
        if( memcmp(h1, h2, plen) )
        {
            printf("wrong: P%u r!\n", plen * 8);
            fails ++;
        }

        vlong_I2OSP(DeltaTo(opctx, offset_s), h1, plen);
        FixedPRNG(testvec->s, h2, plen);
        if( memcmp(h1, h2, plen) )
        {
            printf("wrong: P%u s!\n", plen * 8);
            fails ++;
        }

        sm2sigCtx.x_hdr.status = 0;
        memcpy(&sm2sigSavedCtx, &sm2sigCtx, sizeof(SM2SIG_Ctx_t));

        if( SM2SIG_Verify(&sm2sigCtx.x_hdr, "", 0) )
        {
            printf("forgery undetected: P%u!\n", plen * 8);
            fails ++;
        }

        memcpy(&sm2sigSavedCtx, &sm2sigCtx, sizeof(SM2SIG_Ctx_t));

        if( SM2SIG_Verify(
                &sm2sigCtx.x_hdr,
                testvec->msg,
                strlen(testvec->msg)) )
        {
            printf("rejected mistakenly: P%u!\n", plen * 8);
            fails ++;
        }

        testvec++;
    }

    if( fails ) return EXIT_FAILURE; else return EXIT_SUCCESS;
}
