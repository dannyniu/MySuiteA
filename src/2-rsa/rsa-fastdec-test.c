/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "rsa-codec-der.h"
#include "../0-exec/struct-delta.c.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    void *buf;
    long len, size;
    RSA_Priv_Ctx_Hdr_t *ctx;

    if( argc < 2 ) return 1;

    fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    printf("file length: %ld\n", len);

    buf = malloc(len);
    fread(buf, 1, len, fp);

    // decoding test.

    size = ber_tlv_decode_RSAPrivateKey(NULL, buf, len);
    printf("1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(ctx, buf, len);
    printf(
        "modulus size: %"PRIu32"\n",
        ctx->base.modulus_bits);

    // RSA decryption test.

    vlong_t *C = DeltaTo((&ctx->base), offset_w1);

    for(long i = C->c; --i > 44; ) C->v[i] = 0;
    C->v[ 44] = 0x16f4a33d;
    C->v[ 43] = 0x2e59474d;
    C->v[ 42] = 0x8aff7ef6;
    C->v[ 41] = 0x287a54e8;
    C->v[ 40] = 0xb86c4118;
    C->v[ 39] = 0x9ace37ef;
    C->v[ 38] = 0x09ce559a;
    C->v[ 37] = 0xbf6ca779;
    C->v[ 36] = 0xc8abff6d;
    C->v[ 35] = 0xe979454c;
    C->v[ 34] = 0x24863255;
    C->v[ 33] = 0x8ea878a8;
    C->v[ 32] = 0x3e8a40de;
    C->v[ 31] = 0xc8f0f615;
    C->v[ 30] = 0x4690df69;
    C->v[ 29] = 0x4c9fa56c;
    C->v[ 28] = 0x16f21ab9;
    C->v[ 27] = 0x50b44be5;
    C->v[ 26] = 0xba700d3d;
    C->v[ 25] = 0x57b6c329;
    C->v[ 24] = 0x91822739;
    C->v[ 23] = 0x7a0aab9d;
    C->v[ 22] = 0xf1f8b802;
    C->v[ 21] = 0x99279cc2;
    C->v[ 20] = 0xb59b222c;
    C->v[ 19] = 0x2291fcd5;
    C->v[ 18] = 0x5a1437be;
    C->v[ 17] = 0x7684cad2;
    C->v[ 16] = 0x8abafa42;
    C->v[ 15] = 0x0e53c73e;
    C->v[ 14] = 0x5b24b573;
    C->v[ 13] = 0xf31a2ef8;
    C->v[ 12] = 0x15528659;
    C->v[ 11] = 0x9883ade1;
    C->v[ 10] = 0x44e562d1;
    C->v[  9] = 0xd1121365;
    C->v[  8] = 0x367d881b;
    C->v[  7] = 0xb29f3de5;
    C->v[  6] = 0x63e1eced;
    C->v[  5] = 0xe3f2a3fd;
    C->v[  4] = 0x476cee72;
    C->v[  3] = 0x2051bf1f;
    C->v[  2] = 0x921f5179;
    C->v[  1] = 0xebd57a06;
    C->v[  0] = 0x32030ca6;

    vlong_t *M = rsa_fastdec(ctx);
    vlong_size_t i = 0;
    if( M == DeltaTo((&ctx->base), offset_w2) ) printf("sane\n");

    if( M->v[0] != 65535 )
    {
        printf("RSA Decipher Incorrect!\n");
        return EXIT_FAILURE;
    }
    else
    {
        for(i=1; i<M->c; i++)
            if( M->v[i] )
            {
                printf("RSA Decipher Incorrect!\n");
                return EXIT_FAILURE;
            }
    }

    if( i == M->c ) printf("Textbook RSA Decipher Successful!\n");

    return EXIT_SUCCESS;
}
