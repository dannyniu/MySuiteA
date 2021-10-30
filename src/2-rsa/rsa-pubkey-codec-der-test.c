/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#include "rsa-codec-der.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    FILE *fp;
    void *buf, *buf2;
    long len, size;
    uint32_t *ctx, aux;

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
    
    size = ber_tlv_decode_RSAPrivateKey(1, buf, len, NULL, &aux);
    printf("privkey 1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(2, buf, len, ctx, &aux);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Priv_Base_Ctx_t *)ctx)->modulus_bits);

    // public key encoding test.
    
    len = ber_tlv_encode_RSAPublicKey(1, NULL, 0, ctx, NULL);
    printf("pubkey 1st pass encoding returned: %ld\n", len);

    buf2 = malloc(len);
    len = ber_tlv_encode_RSAPublicKey(2, buf2, size, ctx, NULL);

    fp = fopen(argv[2], "wb");
    fwrite(buf2, 1, len, fp);
    fclose(fp);
    
    // public key decoding test.

    size = ber_tlv_decode_RSAPublicKey(1, buf2, len, NULL, NULL);
    printf("pubkey 1st pass decoding returned: %ld\n", size);
    
    ctx = realloc(ctx, size);
    size = ber_tlv_decode_RSAPublicKey(2, buf2, len, ctx, NULL);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Pub_Ctx_Hdr_t *)ctx)->modulus_bits);
    
    return 0;
}
