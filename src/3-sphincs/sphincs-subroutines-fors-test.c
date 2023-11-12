/* DannyNiu/NJF, 2023-11-07. Public Domain. */

#include "sphincs-subroutines.h"
#include "sphincs-hash-params-family-sha256.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "../test-utils.c.h"

#define N_TEST 16
#define A_TEST 12
#define K_TEST 14

struct {
    SLHDSA_Ctx_Hdr_t header;
    uint8_t buf_n_wotslen_bytes[N_TEST*(2*N_TEST+3)];
    uint8_t buf_n_a_p1_bytes[N_TEST*(A_TEST+1)];
    uint8_t buf_n_k_bytes[N_TEST*K_TEST];
} slhdsa_ctx;

static uint8_t SKseed[N_TEST];
static uint8_t PKseed[N_TEST];
static uint8_t pk1[N_TEST];
static uint8_t pk2[N_TEST];
static uint8_t M[(K_TEST * A_TEST + 7) / 8];
static uint8_t sig[K_TEST*N_TEST*(1+A_TEST)];
static SPHINCS_ADRS_t ADRS_Null;

int main()
{
    bufvec_t funcparams[4];
    int loopcnt = 0, loopstop = 7;

    slhdsa_ctx.header.n = N_TEST;
    slhdsa_ctx.header.a = A_TEST;
    slhdsa_ctx.header.k = K_TEST;

    slhdsa_ctx.header.Hmsg   = SPHINCS_HashParam_Hmsg_SHA256;
    slhdsa_ctx.header.PRF    = SPHINCS_HashParam_PRF_SHA256;
    slhdsa_ctx.header.PRFmsg = SPHINCS_HashParam_PRFmsg_SHA256;
    slhdsa_ctx.header.F      = SPHINCS_HashParam_F_SHA256;
    slhdsa_ctx.header.H      = SPHINCS_HashParam_H_SHA256;
    slhdsa_ctx.header.T      = SPHINCS_HashParam_T_SHA256;

    slhdsa_ctx.header.offset_buf_n_wotslen_bytes =
        slhdsa_ctx.buf_n_wotslen_bytes - (uint8_t *)&slhdsa_ctx;

    slhdsa_ctx.header.offset_buf_n_a_p1_bytes =
        slhdsa_ctx.buf_n_a_p1_bytes - (uint8_t *)&slhdsa_ctx;

    slhdsa_ctx.header.offset_buf_n_k_bytes =
        slhdsa_ctx.buf_n_k_bytes - (uint8_t *)&slhdsa_ctx;

    fread(SKseed, 1, sizeof(SKseed), stdin);
    fread(PKseed, 1, sizeof(PKseed), stdin);

loop: if( loopcnt++ >= loopstop ) return EXIT_SUCCESS;
    fread(M, 1, sizeof(M), stdin);

    funcparams[1].dat = SKseed;
    funcparams[1].len = sizeof(SKseed);
    funcparams[2].dat = PKseed;
    funcparams[2].len = sizeof(PKseed);
    funcparams[3].dat = &ADRS_Null;
    funcparams[3].len = sizeof(SPHINCS_ADRS_t);

    funcparams[0].dat = M;
    funcparams[0].len = sizeof(M);

    //- fprintf(stderr, "fors_sign:\n");
    fors_sign(&slhdsa_ctx.header, funcparams, sig, sizeof(sig));
    //- dumphex(sig, sizeof(sig));

    funcparams[1] = funcparams[0];
    funcparams[0].dat = sig;
    funcparams[0].len = sizeof(sig);

    //- fprintf(stderr, "fors_PKFromSig:\n");
    fors_pkFromSig(
        &slhdsa_ctx.header, funcparams,
        loopcnt == 1 ? pk1 : pk2, sizeof(pk2));
    //- dumphex(loopcnt == 1 ? pk1 : pk2, sizeof(pk2));

    if( loopcnt > 1 && memcmp(pk1, pk2, sizeof(pk1)) )
        return EXIT_FAILURE;
    else goto loop;
}
