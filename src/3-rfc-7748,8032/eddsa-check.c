/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "eddsa.h"
#include "../2-ec/curves-Ed.h"
#include "../2-hash/sha.h"
#include "../2-xof/shake.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"
#include "../test-utils.c.h"

typedef struct {
    EdDSA_Ctx_Hdr_t x_hdr;
    sha384_t hash;
    ecEd448_opctx_t opctx;
    ecEd448_xytz_t Points[4];
    VLONG_T(15) Scalars[2];
} EdDSA_Ctx_t;

EdDSA_Ctx_t eddsaCtx, eddsaSavedCtx;

typedef struct {
    char *d, *sig, *msg;
    EdDSA_Param_t params;
} EdDSA_Test_Vector_t;

EdDSA_Test_Vector_t testvecs[] =
{
    {
        .d =
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60",

        .sig =
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b",

        .msg = "",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
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
    uint8_t H[128];
    int fails = 0;

    EdDSA_Test_Vector_t *testvec = testvecs;
    unsigned pbits, plen;
    size_t len;

    while( testvec->msg )
    {
        pbits = ((ecEd_curve_t *)
                 testvec->params[0].info
                 (ecEd_PtrCurveDef))->pbits;

        plen = (pbits + 8) / 8;

        EdDSA_Keygen(
            &eddsaCtx.x_hdr, testvec->params,
            (GenFunc_t)FixedPRNG, testvec->d);

        EdDSA_Sign(
            &eddsaCtx.x_hdr,
            testvec->msg, strlen(testvec->msg),
            NULL, NULL);

        len = plen * 2;
        EdDSA_Encode_Signature(&eddsaCtx.x_hdr, H, &len);
        EdDSA_Decode_Signature(&eddsaCtx.x_hdr, H, len);

        eddsaCtx.x_hdr.status = 0;
        memcpy(&eddsaSavedCtx, &eddsaCtx, sizeof(EdDSA_Ctx_t));

        if( EdDSA_Verify(&eddsaCtx.x_hdr, "!", 1) )
        {
            printf("forgery undetected: Ed:%u!\n", pbits);
            fails ++;
        }

        memcpy(&eddsaCtx, &eddsaSavedCtx, sizeof(EdDSA_Ctx_t));

        if( !EdDSA_Verify(
                &eddsaCtx.x_hdr,
                testvec->msg,
                strlen(testvec->msg)) )
        {
            printf("rejected mistakenly: Ed:%u!\n", pbits);
            fails ++;
        }

        testvec++;
    }

    if( fails ) return EXIT_FAILURE; else return EXIT_SUCCESS;
}
