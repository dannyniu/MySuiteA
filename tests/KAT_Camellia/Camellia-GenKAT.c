/* DannyNiu/NJF, 2021-07-15. Public Domain. */

#include "camellia.c"

#include <stdio.h>

void dumphex(FILE *fp, uint8_t *dat, size_t len)
{
    for(size_t i=0; i<len; i++)
        fprintf(fp, "%02x", dat[i]);
}

void GenRsp(int bits)
{
    char filename[128];
    FILE *fp;
    int count;

    sprintf(filename, "ECB%d.rsp", bits);
    fp = fopen(filename, "w");

    for(count=0; count<20; count++)
    {
        uint8_t key[32], p[16], c[16];
        uint8_t w[512];

        fread(key, 1, bits/8, stdin);
        Camellia_Ekeygen(bits, (void *)key, (void *)w);
        
        fread(p, 1, 16, stdin);
        Camellia_Encrypt(bits, (void *)p, (void *)w, (void *)c);

        fprintf(fp, "COUNT = %d\n", count);

        fprintf(fp, "KEY = ");
        dumphex(fp, key, bits / 8);
        fputc('\n', fp);

        fprintf(fp, "PLAINTEXT = ");
        dumphex(fp, p, 16);
        fputc('\n', fp);

        fprintf(fp, "CIPHERTEXT = ");
        dumphex(fp, c, 16);
        fputc('\n', fp);

        fputc('\n', fp);
    }
}

int main()
{
    GenRsp(128);
    GenRsp(192);
    GenRsp(256);
    return 0;
}
