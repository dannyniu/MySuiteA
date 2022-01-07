/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "rsa-codec-der.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    void *buf, *buf2, *buf3;
    long len, size;
    uint32_t *ctx;

    if( argc < 3 ) return 1;

    fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    buf = malloc(len);
    fread(buf, 1, len, fp);

    fclose(fp);
    fp = NULL;

    // private key decoding test.
    
    size = ber_tlv_decode_RSAPrivateKey(NULL, buf, len);
    printf("privkey 1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(ctx, buf, len);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Priv_Base_Ctx_t *)ctx)->modulus_bits);

    // public key exporting test.
    
    len = ber_tlv_export_RSAPublicKey(ctx, NULL, 0);
    printf("pubkey 1st pass exporting returned: %ld\n", len);

    buf2 = malloc(len);
    len = ber_tlv_export_RSAPublicKey(ctx, buf2, size);

    fp = fopen(argv[2], "wb");
    fwrite(buf2, 1, len, fp);
    fclose(fp);
    
    // public key decoding test.

    size = ber_tlv_decode_RSAPublicKey(NULL, buf2, len);
    printf("pubkey 1st pass decoding returned: %ld\n", size);
    
    ctx = realloc(ctx, size);
    size = ber_tlv_decode_RSAPublicKey(ctx, buf2, len);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Pub_Ctx_Hdr_t *)ctx)->modulus_bits);

    // public key encoding test.

    len = ber_tlv_encode_RSAPublicKey(ctx, NULL, 0);
    printf("pubkey 1stpass encoding returned: %ld\n", len);

    buf3 = malloc(len);
    len = ber_tlv_encode_RSAPublicKey(ctx, buf3, len);
    
    if( memcmp(buf2, buf3, len) )
    {
        printf("memcmp differs\n");
        return EXIT_FAILURE;
    }

    printf("the test passed\n");
    return EXIT_SUCCESS;
}
