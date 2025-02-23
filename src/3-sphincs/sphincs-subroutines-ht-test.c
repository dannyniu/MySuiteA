/* DannyNiu/NJF, 2023-11-06. Public Domain. */

#include "sphincs-subroutines.h"
#include "sphincs-hash-params-family-sha256.h"
#include "../0-datum/endian.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../test-utils.c.h"

#define N_TEST 16
#define D_TEST 7
#define H_APOS_TEST 9

struct {
    SLHDSA_Ctx_Hdr_t header;
    uint8_t buf_n_bytes[N_TEST];
    uint8_t buf_n_wotslen_bytes[N_TEST*(2*N_TEST+3)];
    uint8_t buf_n_hapos_p1_bytes[N_TEST*(H_APOS_TEST+1)];
} slhdsa_ctx;

static uint8_t SKseed[N_TEST];
static uint8_t PKseed[N_TEST];
static uint8_t PKroot[N_TEST];
static uint8_t M[N_TEST];
static uint8_t sig[D_TEST*N_TEST*(2*N_TEST+3+H_APOS_TEST)];
static SPHINCS_ADRS_t ADRS_Null;
static uint32_t idx_tree[3];

int main()
{
    bufvec_t funcparams[4];
    int loopcnt = 6;
    int ret;

    slhdsa_ctx.header.n = N_TEST;
    slhdsa_ctx.header.d = D_TEST;
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

    ADRS_Null.layeraddr = htobe32(D_TEST - 1);

    //- fprintf(stderr, "ht_keygen:\n");
    xmss_auth_path_and_root_node(
        &slhdsa_ctx.header, funcparams+1, PKroot, sizeof(PKroot), 0, NULL, 0);
    //- fprintf(stderr, "PK.root: "); dumphex(PKroot, sizeof(PKroot));

    funcparams[0].dat = M;
    funcparams[0].len = sizeof(M);

    //- fprintf(stderr, "ht_sign:\n");
    ht_sign(&slhdsa_ctx.header, funcparams, sig, sizeof(sig), idx_tree, 0);
    //- dumphex(sig, sizeof(sig));

    funcparams[1].dat = sig;
    funcparams[1].len = sizeof(sig);
    funcparams[3].dat = PKroot;
    funcparams[3].len = sizeof(PKroot);

    //- fprintf(stderr, "ht_verify:\n");
    ret = ht_verify(&slhdsa_ctx.header, funcparams, idx_tree, 0);

    if( !ret )
        return EXIT_FAILURE;
    else goto loop;
}
