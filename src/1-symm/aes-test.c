/* DannyNiu/NJF, 2018-01-31. Public Domain. */

#include "rijndael.h"
#include "../0-datum/endian.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void scanhex(char *restrict out, size_t len, const char *restrict in)
{
    int n;
    while( sscanf(in, " %2"SCNx8"%n", (out++), &n) && len-- ) in += n;
}

int main(int argc, char *argv[])
{
    static char line[256], word[256];
    static char k[32], w[240], ct[16], pt[16], xt[16];
    intptr_t (*bc)(int) = iAES128;
    int i, l=-1;

    if( argc < 2 ) return 1;
    if( !strcmp(argv[1], "128") ) bc = iAES128;
    if( !strcmp(argv[1], "192") ) bc = iAES192;
    if( !strcmp(argv[1], "256") ) bc = iAES256;
    
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
}
