/* DannyNiu/NJF, 2018-01-31. Public Domain. */

#include "camellia.h"
#include "../test-utils.c.h"

int main(int argc, char *argv[])
{
    static char line[256], word[256];
    static uint8_t k[32], w[64], ct[16], pt[16], xt[16];
    iCryptoObj_t bc = iCamellia128;
    int i, l=-1;

    if( argc < 2 ) return 1;
    if( !strcmp(argv[1], "128") ) bc = iCamellia128;
    if( !strcmp(argv[1], "192") ) bc = iCamellia192;
    if( !strcmp(argv[1], "256") ) bc = iCamellia256;
    
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
