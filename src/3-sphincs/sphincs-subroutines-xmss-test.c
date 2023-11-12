/* DannyNiu/NJF, 2023-11-05. Public Domain. */

#include "sphincs-subroutines.h"
#include "sphincs-hash-params-family-sha256.h"

#include <stdlib.h>
#include <string.h>
#include "../test-utils.c.h"

#define N_TEST 16
#define H_APOS_TEST 9
#define IDX_TEST 6

struct {
    SLHDSA_Ctx_Hdr_t header;
    uint8_t buf_n_bytes[N_TEST];
    uint8_t buf_n_wotslen_bytes[N_TEST*(2*N_TEST+3)];
    uint8_t buf_n_hapos_p1_bytes[N_TEST*(H_APOS_TEST+1)];
} slhdsa_ctx;

static uint8_t SKseed[N_TEST];
static uint8_t PKseed[N_TEST];
static uint8_t pk1[N_TEST];
static uint8_t pk2[N_TEST];
static uint8_t M[N_TEST];
static uint8_t sig[N_TEST*(2*N_TEST+3+H_APOS_TEST)];
static SPHINCS_ADRS_t ADRS_Null;

int main()
{
    bufvec_t funcparams[4];
    int loopcnt = 8;

    slhdsa_ctx.header.n = N_TEST;
    slhdsa_ctx.header.hapos = H_APOS_TEST;
    slhdsa_ctx.header.lgw = 4;
    slhdsa_ctx.header.wots.w = 16;
    slhdsa_ctx.header.wots.len1 = 2*N_TEST;
    slhdsa_ctx.header.wots.len2 = 3;
    slhdsa_ctx.header.wots.len = 2*N_TEST + 3;

    slhdsa_ctx.header.Hmsg   = SPHINCS_HashParam_Hmsg_SHA256;
    slhdsa_ctx.header.PRF    = SPHINCS_HashParam_PRF_SHA256;
    slhdsa_ctx.header.PRFmsg = SPHINCS_HashParam_PRFmsg_SHA256;
    slhdsa_ctx.header.F      = SPHINCS_HashParam_F_SHA256;
    slhdsa_ctx.header.H      = SPHINCS_HashParam_H_SHA256;
    slhdsa_ctx.header.T      = SPHINCS_HashParam_T_SHA256;

    slhdsa_ctx.header.offset_buf_n_bytes =
        slhdsa_ctx.buf_n_bytes - (uint8_t *)&slhdsa_ctx;

    slhdsa_ctx.header.offset_buf_n_wotslen_bytes =
        slhdsa_ctx.buf_n_wotslen_bytes - (uint8_t *)&slhdsa_ctx;

    slhdsa_ctx.header.offset_buf_n_hapos_p1_bytes =
        slhdsa_ctx.buf_n_hapos_p1_bytes - (uint8_t *)&slhdsa_ctx;

loop: if( !loopcnt-- ) return EXIT_SUCCESS;
    fread(SKseed, 1, sizeof(SKseed), stdin);
    fread(PKseed, 1, sizeof(PKseed), stdin);
    fread(M, 1, sizeof(M), stdin);

    funcparams[1].dat = SKseed;
    funcparams[1].len = sizeof(SKseed);
    funcparams[2].dat = PKseed;
    funcparams[2].len = sizeof(PKseed);
    funcparams[3].dat = &ADRS_Null;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    //- fprintf(stderr, "xmss_root_node:\n");
    xmss_auth_path_and_root_node(
        &slhdsa_ctx.header, funcparams+1, pk1, sizeof(pk1), 0, NULL, 0);
    //- dumphex(pk1, sizeof(pk1));

    funcparams[0].dat = M;
    funcparams[0].len = sizeof(M);

    //- fprintf(stderr, "xmss_sign:\n");
    xmss_sign(&slhdsa_ctx.header, funcparams, sig, sizeof(sig), IDX_TEST);
    //- dumphex(sig, sizeof(sig));

    funcparams[1] = funcparams[0];
    funcparams[0].dat = sig;
    funcparams[0].len = sizeof(sig);

    //- fprintf(stderr, "xmss_PKFromSig:\n");
    xmss_PKFromSig(&slhdsa_ctx.header, funcparams, pk2, sizeof(pk2), IDX_TEST);
    //- dumphex(pk2, sizeof(pk2));

    if( memcmp(pk1, pk2, sizeof(pk1)) )
        return EXIT_FAILURE;
    else goto loop;
}
