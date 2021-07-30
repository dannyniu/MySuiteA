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
    
    size = ber_tlv_decode_RSAPrivateKey(1, buf, len, NULL, &aux);
    printf("1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(2, buf, len, ctx, &aux);
    printf(
        "modulus size: %"PRIu32"\n",
        ((RSA_Private_Context_Base_t *)ctx)->modulus_bits);

    // encoding test.
    
    size = ber_tlv_encode_RSAPrivateKey(1, buf2, len, ctx, NULL);
    printf("1st pass encoding returned: %ld\n", size);

    size = ber_tlv_encode_RSAPrivateKey(2, buf2, len, ctx, NULL);
    
    printf("memcmp-1 returned %d\n", memcmp(buf, buf2, len));

    ber_tlv_decode_RSAPrivateKey(1, buf2, len, ctx, &aux);
    ber_tlv_decode_RSAPrivateKey(2, buf2, len, ctx, &aux);
    
    ber_tlv_encode_RSAPrivateKey(1, buf, len, ctx, NULL);
    ber_tlv_encode_RSAPrivateKey(2, buf, len, ctx, NULL);

    printf("memcmp-2 returned %d\n", memcmp(buf, buf2, len));

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

    return 0;
}
