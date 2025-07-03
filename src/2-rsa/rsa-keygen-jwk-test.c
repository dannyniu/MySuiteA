/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "rsa.h"
#include "rsa-codec-der.h"
#include "rsa-codec-jwk.h"
#include "../2-xof/gimli-xof.h"
#include "../test-utils.c.h"

static gimli_xof_t gx;

#define DUMP_CONTEXT_WORDS 0

void dump_ctx_words(const uint32_t *ctx, size_t size)
{
    if( !ctx ) return;
#if DUMP_CONTEXT_WORDS
    for(size_t i=0; i*4<size; i++)
    {
        printf(
            "%08x%c", ctx[i],
            (4 - i % 4 == 1) ? '\n' : ' ');
    }
#else /* DUMP_CONTEXT_WORDS */
    (void)size;
#endif /* DUMP_CONTEXT_WORDS */
}

int main(int argc, char *argv[])
{
    size_t size, len;
    uint8_t *der1, *der2;
    RSA_Priv_Ctx_Hdr_t *ctx;
    RSA_Priv_Param_t p_rsa = {
        [0].aux = 600, // modulus bits.
        [1].aux = 6, // primes count
    };

    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( argc >= 2 )
        Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
    Gimli_XOF_Final(&gx);

    // Experiment 1: RSA Key Generation.
    size = rsa_keygen(NULL, p_rsa, NULL, NULL);
    printf("sizeof(ctx-priv): %zu\n", size);

    ctx = malloc(size);
    rsa_keygen(ctx, p_rsa, (GenFunc_t)Gimli_XOF_Read, &gx);

    dump_ctx_words((void *)ctx, size);

    // Experiment 2: Encoding the Generated Private Key.
    len = ber_tlv_encode_RSAPrivateKey(ctx, NULL, 0);
    printf("sizeof(der-priv): %zu\n", len);

    der1 = malloc(len);
    ber_tlv_encode_RSAPrivateKey(ctx, der1, len);

    FILE *r8p = fopen("/tmp/rsa-8p.der", "wb");
    fwrite(der1, 1, len, r8p);
    fclose(r8p);

    // Experiment 3: Decode and Encode and Compare.

    json_io_t jctx = {};
    if( !RSAPrivateKey_ToJWK(&jctx, der1, len) )
    {
        printf("JWK Encoding Failed.\n");
        return EXIT_FAILURE;
    }
    jctx.json = calloc(1, (jctx.limit = jctx.offset) + 1);
    jctx.offset = 0;
    RSAPrivateKey_ToJWK(&jctx, der1, len);

    json_io_t jstr = jctx;
    jstr.offset = 0;
    size = RSAPrivateKey_FromJWK(jstr, NULL, 0);
    der2 = malloc(size);
    RSAPrivateKey_FromJWK(jstr, der2, size);
    printf("sizeof(der-priv): %zu\n", size);

    // -- Result of the Compare --

    if( len != size )
    {
        printf("Length Different\n");
        return EXIT_FAILURE;
    }

    else if( memcmp(der1, der2, len) )
    {
        printf("Encoding Different\n");
        return EXIT_FAILURE;
    }

    else
    {
        printf("the test passed\n");
        return EXIT_SUCCESS;
    }
}
