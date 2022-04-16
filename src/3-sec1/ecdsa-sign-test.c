/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecdsa.h"
#include "../2-ec/curves-secp.h"
#include "../2-hash/sha.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"
#include "../test-utils.c.h"

typedef struct {
    ECC_Hash_Ctx_Hdr_t x_hdr;
    sha384_t hash;
    ecp384_opctx_t opctx;
    ecp384_xyz_t Points[4];
    VLONG_T(14) Scalars[2];
} ECDSA_Ctx_t;

ECDSA_Ctx_t ecdsaCtx, ecdsaSavedCtx;

typedef struct {
    char *k, *d, *r, *s, *msg;
    ECDSA_Param_t params;
} ECDSA_Test_Vector_t;

ECDSA_Test_Vector_t testvecs[] =
{
    {
        .k = 
        "7A1A7E52797FC8CAAA435D2A4DACE391"
        "58504BF204FBE19F14DBB427FAEE50AE",

        .d = 
        "C477F9F65C22CCE20657FAA5B2D1D812"
        "2336F851A508A1ED04E479C34985BF96",

        .r =
        "2B42F576D07F4165FF65D1F3B1500F81"
        "E44C316F1F0B3EF57325B69ACA46104F",

        .s = 
        "DC42C2122D6392CD3E3A993A89502A81"
        "98C1886FE69D262C4B329BDB6B63FAF1",

        .msg = "Example of ECDSA with P-256",

        .params[0].info = i_secp256r1,
        .params[1].info = iSHA256,
        .params[0].aux = 0,
        .params[1].aux = 0,
    },
    
    {
        .k = 
        "2E44EF1F8C0BEA8394E3DDA81EC6A784"
        "2A459B534701749E2ED95F054F013768"
        "0878E0749FC43F85EDCAE06CC2F43FEF",

        .d = 
        "F92C02ED629E4B48C0584B1C6CE3A3E3"
        "B4FAAE4AFC6ACB0455E73DFC392E6A0A"
        "E393A8565E6B9714D1224B57D83F8A08",

        .r =
        "30EA514FC0D38D8208756F068113C7CA"
        "DA9F66A3B40EA3B313D040D9B57DD41A"
        "332795D02CC7D507FCEF9FAF01A27088",

        .s = 
        "CC808E504BE414F46C9027BCBF78ADF0"
        "67A43922D6FCAA66C4476875FBB7B94E"
        "FD1F7D5DBE620BFB821C46D549683AD8",

        .msg = "Example of ECDSA with P-384",

        .params[0].info = i_secp384r1,
        .params[1].info = iSHA384,
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

    ECDSA_Test_Vector_t *testvec = testvecs;
    unsigned plen;

    while( testvec->msg )
    {
        plen = ((ecp_curve_t *)testvec->params[0].info(ptrCurveDef))->plen;
        plen = plen < 64 ? plen : 64;
        
        ECDSA_Keygen(
            &ecdsaCtx.x_hdr, testvec->params,
            (GenFunc_t)FixedPRNG, testvec->d);

        ECDSA_Sign(
            &ecdsaCtx.x_hdr,
            testvec->msg, strlen(testvec->msg),
            (GenFunc_t)FixedPRNG, testvec->k);

        opctx = DeltaTo((&ecdsaCtx.x_hdr), offset_opctx);

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

        ecdsaCtx.x_hdr.status = 0;
        memcpy(&ecdsaSavedCtx, &ecdsaCtx, sizeof(ECDSA_Ctx_t));

        if( ECDSA_Verify(&ecdsaCtx.x_hdr, "", 0) )
        {
            printf("forgery undetected: P%u!\n", plen * 8);
            fails ++;
        }

        memcpy(&ecdsaSavedCtx, &ecdsaCtx, sizeof(ECDSA_Ctx_t));

        if( ECDSA_Verify(
                &ecdsaCtx.x_hdr,
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
