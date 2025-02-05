/* DannyNiu/NJF, 2025-01-28. Public Domain. */

#include "ascon-hash.h"

#include "../test-utils.c.h"

char line[8192], word[64];
uint8_t msg[4096];
uint8_t out[128], ref[128];
size_t msglen, mdlen;

void Ascon_Hash_Feed(ascon_hash256_t *hctx, size_t outlen)
{
    size_t iolen = 0;
    uint8_t *ptr = msg;

    mysrand((unsigned long)time(NULL));

    while( (size_t)(ptr - msg) < msglen )
    {
        iolen = myrand()+1;
        iolen = iolen > msglen - (ptr-msg) ? msglen - (ptr-msg) : iolen;
        Ascon_Hash256_Update(hctx, ptr, iolen);
        ptr += iolen;
    }

    Ascon_Hash256_Final(hctx, out, outlen);
}

int test_ascon_hash256(void)
{
    int i, l=-1;
    int ret = EXIT_SUCCESS;
    ascon_hash256_t hctx;

    while( fgets(line, sizeof(line), stdin) )
    {
        *word = '\0';
        sscanf(line, "%s", word);

        if( !strlen(word) && l >= 0 )
        {
            Ascon_Hash256_Init(&hctx);

            Ascon_Hash_Feed(&hctx, mdlen);
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

        if( !strcmp(word, "MD") )
        {
            sscanf(line, "%s = %n", word, &i);
            mdlen = (strlen(line) - i) / 2;
            scanhex(ref, mdlen, line+i);
        }
    }

    return ret;
}

int main(void)
{
    return test_ascon_hash256();
}
