/* DannyNiu/NJF, 2021-06-23. Public Domain. */

#include "seed.h"
#include "../test-utils.c.h"

int main(int argc, char *argv[])
{
    static char line[256], word[256];
    static uint8_t k[32], w[128], ct[16], pt[16], xt[16];
    iCryptoObj_t bc = iSEED;
    int i, l=-1;

    argc = 0, argv = NULL; // To silence the unused argument warning.

    while( fgets(line, sizeof(line), stdin) )
    {
        *word = '\0'; sscanf(line, "%s", word);
        
        if( !strlen(word) && l>=0 ) {
            ENC_FUNC(bc)(pt, xt, w);
            if( memcmp(xt, ct, bc(blockBytes)) )
                printf("Encryption Failure at Line %d\n", l);

            DEC_FUNC(bc)(ct, xt, w);
            if( memcmp(xt, pt, bc(blockBytes)) )
                printf("Decryption Failure at Line %d\n", l);

            l = -1;
        }
        
        if( !strcmp(word, "COUNT") )
            sscanf(line, "%s = %d", word, &l);

        if( !strcmp(word, "KEY") ) {
            sscanf(line, "%s = %n", word, &i);
            scanhex(k, bc(keyBytes), line+i);
            KSCHD_FUNC(bc)(k, w);
        }

        if( !strcmp(word, "CIPHERTEXT") ) {
            sscanf(line, "%s = %n", word, &i);
            scanhex(ct, bc(blockBytes), line+i);
        }
        if( !strcmp(word, "PLAINTEXT") ) {
            sscanf(line, "%s = %n", word, &i);
            scanhex(pt, bc(blockBytes), line+i);
        }
    }

    return 0;
}
