/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "rsa-codec-der.h"

#define DUMP_CONTEXT_WORDS 0

#if DUMP_CONTEXT_WORDS
void dump_ctx_words(const uint32_t *ctx, size_t size)
{
    if( !ctx ) return;
    for(size_t i=0; i*4<size; i++)
    {
        printf(
            "%08x%c", ctx[i],
            (4 - i % 4 == 1) ? '\n' : ' ');
    }
}
#else
#define dump_ctx_words(...) ((void)0)
#endif /* DUMP_CONTEXT_WORDS */

#include "../test-utils.c.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    void *buf, *buf2;
    long len, size;
    uint32_t *ctx;

    if( argc < 2 ) return 1;

    fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    printf("file length: %ld\n", len);

    buf = malloc(len);
    buf2 = malloc(len);
    fread(buf, 1, len, fp);
    memset(buf2, 0, len);

    fclose(fp);
    fp = NULL;

    // decoding test.

    size = ber_tlv_decode_RSAPrivateKey(NULL, buf, len); //dumphex(buf,len);
    printf("1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(ctx, buf, len);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Priv_Base_Ctx_t *)ctx)->modulus_bits);

    dump_ctx_words((void *)ctx, size);

    // encoding test.

    size = ber_tlv_encode_RSAPrivateKey(ctx, NULL, 0);
    printf("1st pass encoding returned: %ld\n", size);

    size = ber_tlv_encode_RSAPrivateKey(ctx, buf2, len); //dumphex(buf2,len);

    if( memcmp(buf, buf2, len) )
    {
        printf("1st memcmp differs\n");
        return EXIT_FAILURE;
    }

    ber_tlv_decode_RSAPrivateKey(NULL, buf2, len);
    ber_tlv_decode_RSAPrivateKey(ctx, buf2, len);

    ber_tlv_encode_RSAPrivateKey(ctx, NULL, 0);
    ber_tlv_encode_RSAPrivateKey(ctx, buf, len);

    if( memcmp(buf, buf2, len) )
    {
        printf("2nd memcmp differs\n");
        return EXIT_FAILURE;
    }

#if 0
    FILE *od = popen("od -t x1", "w");
    if( od )
    {
        fwrite(buf2, 1, len, od);
        pclose(od);
    }
    else perror("popen");
#endif

#if 0
    for(long i=0; i*4<size; i++)
        printf("%08x%c", ctx[i], i%4==3 ? '\n' : ' ');
    putchar('\n');
#endif

    printf("the test passed\n");
    return EXIT_SUCCESS;
}
