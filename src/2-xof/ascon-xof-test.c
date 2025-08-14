/* DannyNiu/NJF, 2025-01-27. Public Domain. */

#include "ascon-xof.h"

#include "../test-utils.c.h"

char line[8192], word[64];
uint8_t msg[4096];
uint8_t out[512], ref[512];
uint8_t z[256];
size_t zlen, msglen, mdlen;

void Ascon_Xof_Feed(ascon_xof128_t *hctx, size_t outlen)
{
    size_t iolen = 0;
    uint8_t *ptr = msg;

    mysrand((unsigned long)time(NULL));

    while( (size_t)(ptr - msg) < msglen )
    {
        iolen = myrand()+1;
        iolen = iolen > msglen - (ptr-msg) ? msglen - (ptr-msg) : iolen;
        Ascon_XOF128_Write(hctx, ptr, iolen);
        ptr += iolen;
    }

    Ascon_XOF128_Final(hctx);
    ptr = out;

    while( outlen > 0 )
    {
        iolen = myrand()+1;
        iolen = iolen > outlen ? outlen : iolen;

        Ascon_XOF128_Read(hctx, ptr, iolen);
        ptr += iolen;
        outlen -= iolen;
    }
}

int test_ascon_xof128(bool cxof)
{
    int i, l=-1;
    int ret = EXIT_SUCCESS;
    ascon_xof128_t hctx;

    while( fgets(line, sizeof(line), stdin) )
    {
        *word = '\0';
        sscanf(line, "%s", word);

        if( !strlen(word) && l >= 0 )
        {
            if( cxof )
            {
                Ascon_CXOF128_KInit(&hctx, z, zlen);
            }
            else
            {
                Ascon_XOF128_Init(&hctx);
            }

            Ascon_Xof_Feed(&hctx, mdlen);
            if( memcmp(out, ref, mdlen) )
            {
                printf("Hash digest mismatch at line %d\n", l);
                dumphex(out, mdlen);
                dumphex(ref, mdlen);
                ret = EXIT_FAILURE;
            }

            l = -1;
        }

        if( !strcmp(word, "Count") )
            sscanf(line, "%s = %d", word, &l);

        if( !strcmp(word, "Msg") )
        {
            sscanf(line, "%s = %n", word, &i);
            msglen = (strlen(line) - i) / 2;
            scanhex(msg, msglen, line+i);
        }

        if( !strcmp(word, "Z") )
        {
            sscanf(line, "%s = %n", word, &i);
            zlen = (strlen(line) - i) / 2;
            scanhex(z, zlen, line+i);
        }

        if( !strcmp(word, "MD") )
        {
            sscanf(line, "%s = %n", word, &i);
            mdlen = (strlen(line) - i) / 2;
            scanhex(ref, mdlen, line+i);
        }
    }

    return ret;
}

int main(int argc, char *argv[])
{
    return test_ascon_xof128(strcmp(argv[1], "cxof") == 0);
}
