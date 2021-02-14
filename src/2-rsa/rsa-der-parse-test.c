/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    FILE *fp;
    void *buf;
    long len, size;
    uint32_t *ctx, aux;

    if( argc < 2 ) return 1;

    fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    buf = malloc(len);
    fread(buf, 1, len, fp);

    size = ber_tlv_decode_RSAPrivateKey(
        1, buf, len,
        NULL, &aux);

    printf("1st pass decoding returned: %ld\n", size);

    ctx = malloc(size);
    size = ber_tlv_decode_RSAPrivateKey(
        2, buf, len,
        ctx, &aux);

    for(long i=0; i*4<size; i++)
        printf("%08x%c", ctx[i], i%4==3 ? '\n' : ' ');
    putchar('\n');

    return 0;
}
