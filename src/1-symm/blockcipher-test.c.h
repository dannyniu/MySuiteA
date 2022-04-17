/* DannyNiu/NJF, 2022-01-06. Public Domain. */

#ifndef blockcipher_test_c_h
#define blockcipher_test_c_h 1

#include "rijndael.h"
#include "../1-symm-national/aria.h"
#include "../1-symm-national/camellia.h"
#include "../1-symm-national/seed.h"
#include "../1-symm-national/sm4.h"

#include "../test-utils.c.h"

static char line[256], word[256];
static uint8_t k[32], w[320], ct[16], pt[16], xt[16];

#endif /* blockcipher_test_c_h */

#ifndef bc
#error The blockcipher query object ``bc'' is not defined!
#endif /* bc */

int glue(blockcipher_test_,bc)(void)
{
    int i, l=-1;
    int ret = EXIT_SUCCESS;

    while( fgets(line, sizeof(line), stdin) )
    {
        *word = '\0'; sscanf(line, "%s", word);

        if( !strlen(word) && l>=0 )
        {
            ENC_FUNC(bc)(pt, xt, w);
            if( memcmp(xt, ct, bc(blockBytes)) )
            {
                printf("Encryption Failure at Line %d\n", l);
                ret = EXIT_FAILURE;
            }

            DEC_FUNC(bc)(ct, xt, w);
            if( memcmp(xt, pt, bc(blockBytes)) )
            {
                printf("Decryption Failure at Line %d\n", l);
                ret = EXIT_FAILURE;
            }

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

    return ret;
}
