/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "rsa-codec-jwk.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    void *der1, *der2;
    long len, size;

    if( argc < 2 ) return 1;

    fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    der1 = malloc(len);
    fread(der1, 1, len, fp);

    fclose(fp);
    fp = NULL;

    json_io_t jctx = {};
    if( !RSAPublicKey_ToJWK(&jctx, der1, len) )
    {
        printf("JWK Encoding Failed.\n");
        return EXIT_FAILURE;
    }
    jctx.json = calloc(1, (jctx.limit = jctx.offset) + 1);
    jctx.offset = 0;
    RSAPublicKey_ToJWK(&jctx, der1, len);

    printf("JWK: %s\n", jctx.json);

    json_io_t jstr = jctx;
    jstr.offset = 0;
    size = RSAPublicKey_FromJWK(jstr, NULL, 0);
    der2 = malloc(size);
    RSAPublicKey_FromJWK(jstr, der2, size);
    printf("sizeof(der-pub): %zu\n", size);

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
