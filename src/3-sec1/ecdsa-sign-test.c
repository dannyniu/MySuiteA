/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "ecdsa.h"
#include "../2-ec/curves-secp.h"
#include "../2-hash/sha.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"
#include "../test-utils.c.h"

typedef struct {
    ECDSA_Priv_Ctx_Hdr_t x_hdr;
    sha384_t hash;
    ecp384_opctx_t opctx;
    ecp384_xyz_t Points[4];
    VLONG_T(14) Scalars[2];
} ECDSA_Priv_Ctx_t;

char k_fixrand1[] =
    "7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE";

char k_fixrand2[] =
    "2E44EF1F8C0BEA8394E3DDA81EC6A7842A459B534701749E2ED95F054F013768"
    "0878E0749FC43F85EDCAE06CC2F43FEF";

char d_p256[] =
    "C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96";

char d_p384[] =
    "F92C02ED629E4B48C0584B1C6CE3A3E3B4FAAE4AFC6ACB0455E73DFC392E6A0A"
    "E393A8565E6B9714D1224B57D83F8A08";

char r_p256[] =
    "2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F";

char s_p256[] =
    "DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1";

char r_p384[] =
    "30EA514FC0D38D8208756F068113C7CADA9F66A3B40EA3B313D040D9B57DD41A"
    "332795D02CC7D507FCEF9FAF01A27088";

char s_p384[] =
    "CC808E504BE414F46C9027BCBF78ADF067A43922D6FCAA66C4476875FBB7B94E"
    "FD1F7D5DBE620BFB821C46D549683AD8";

char msg_p256[] = "Example of ECDSA with P-256";
char msg_p384[] = "Example of ECDSA with P-384";

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(void) // (int argc, char *argv[])
{
    ECDSA_Param_t ecdsaParam;
    ECDSA_Priv_Ctx_t ecdsaCtx;
    ecp_opctx_t *opctx;
    uint8_t h1[64], h2[64];
    int fails = 0;

    ecdsaParam[0] = (CryptoParam_t){ .info = i_secp256r1, .aux = 0, };
    ecdsaParam[1] = (CryptoParam_t){ .info = iSHA256, .aux = 0, };
    ECDSA_Keygen(&ecdsaCtx.x_hdr, ecdsaParam, (GenFunc_t)FixedPRNG, d_p256);
    ECDSA_Sign(
        &ecdsaCtx.x_hdr,
        msg_p256, strlen(msg_p256),
        (GenFunc_t)FixedPRNG, k_fixrand1);

    opctx = DeltaTo((&ecdsaCtx.x_hdr), offset_opctx);
    
    vlong_I2OSP(DeltaTo(opctx, offset_r), h1, 32);
    FixedPRNG(r_p256, h2, 32);
    if( memcmp(h1, h2, 32) )
    {
        printf("wrong: P256 r!\n");
        fails ++;
    }

    vlong_I2OSP(DeltaTo(opctx, offset_s), h1, 32);
    FixedPRNG(s_p256, h2, 32);
    if( memcmp(h1, h2, 32) )
    {
        printf("wrong: P256 s!\n");
        fails ++;
    }

    ecdsaParam[0] = (CryptoParam_t){ .info = i_secp384r1, .aux = 0, };
    ecdsaParam[1] = (CryptoParam_t){ .info = iSHA384, .aux = 0, };
    ECDSA_Keygen(&ecdsaCtx.x_hdr, ecdsaParam, (GenFunc_t)FixedPRNG, d_p384);
    ECDSA_Sign(
        &ecdsaCtx.x_hdr,
        msg_p384, strlen(msg_p384),
        (GenFunc_t)FixedPRNG, k_fixrand2);

    opctx = DeltaTo((&ecdsaCtx.x_hdr), offset_opctx);
    
    vlong_I2OSP(DeltaTo(opctx, offset_r), h1, 48);
    FixedPRNG(r_p384, h2, 48);
    if( memcmp(h1, h2, 48) )
    {
        printf("wrong: P384 r!\n");
        fails ++;
    }

    vlong_I2OSP(DeltaTo(opctx, offset_s), h1, 48);
    FixedPRNG(s_p384, h2, 48);
    if( memcmp(h1, h2, 48) )
    {
        printf("wrong: P384 s!\n");
        fails ++;
    }

    if( fails ) return EXIT_FAILURE; else return EXIT_SUCCESS;
}
