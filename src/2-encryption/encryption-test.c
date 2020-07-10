/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#include "chacha20-poly1305.h"
#include "gcm-aes.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static char line[128], word[128];
static uint8_t k[32], iv[12], a[32], p[1024], c[1024], s[16], t[16], x[1024];
static size_t len, alen;

static gcm_aes256_t gcm;

void *scanhex(uint8_t *restrict out, size_t length, char const *restrict in)
{
    int n;
    while( isxdigit((int)*in) && length-- &&
           sscanf(in, " %2"SCNx8" %n", out, &n) )
    {
        in += n;
        out++;
    }
    return out;
}

void dumphex(uint8_t *data, size_t length)
{
    for(size_t i=0; i<length; i+=16) {
        for(size_t j=0; j<16; j++)
            if( i+j < len ) printf("%02x ", data[i+j]);

        printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    int i;
    uint8_t *ptr = NULL, *tmp;
    size_t *acc = NULL;
    uintptr_t (*aead)(int) = iGCM_AES128;

    if( argc < 3 ) return 1;
    if( !strcmp(argv[1], "128") ) aead = iGCM_AES128;
    if( !strcmp(argv[1], "192") ) aead = iGCM_AES192;
    if( !strcmp(argv[1], "256") ) aead = iGCM_AES256;
    if( !strcmp(argv[1], "20") ) aead = iChaCha_AEAD;

    freopen(argv[2], "r", stdin);
    
    while( fgets(line, sizeof(line), stdin) )
    {
        if( sscanf(line, " %[:] %n", x, &i) && ptr )
        {
        doscan:
            tmp = scanhex(ptr, 16, line+i);
            if( acc ) *acc += (size_t)(tmp-ptr);
            ptr = tmp;
            continue;
        }
        else
        {
            sscanf(line, "%[^ :] : %n", word, &i);

            ;;;; if( !strcmp(word, "K") ) {
                ptr = k;
                acc = NULL;
                goto doscan;
            }
            else if( !strcmp(word, "IV") ) {
                ptr = iv;
                acc = NULL;
                goto doscan;
            }
            else if( !strcmp(word, "P") ) {
                ptr = p;
                acc = &len;
                *acc = 0;
                goto doscan;
            }
            else if( !strcmp(word, "C") ) {
                ptr = c;
                acc = &len;
                *acc = 0;
                goto doscan;
            }
            else if( !strcmp(word, "A") ) {
                ptr = a;
                acc = &alen;
                *acc = 0;
                goto doscan;
            }
            else if( !strcmp(word, "T") ) {
                ptr = t;
                acc = NULL;
                goto doscan;
            }
            else { ptr=NULL; acc=NULL; }
        }
    }

    printf("%s\n", argv[2]);

    KINIT_FUNC(aead)(&gcm, k, KEY_BYTES(aead));
    AENC_FUNC(aead)((void *)&gcm, iv, alen, a, len, p, x, 16, s);
    if( memcmp(s, t, 16) ) printf("Encryption Failed: Tag Wrong!\n");
    if( memcmp(c, x, len) ) printf("Encryption Failed: Ciphertext Wrong!\n");
    ptr = ADEC_FUNC(aead)((void *)&gcm, iv, alen, a, len, c, x, 16, t);
    if( !ptr ) printf("Decryption Errornously Returned FAIL\n");
    if( memcmp(p, x, len) ) printf("Decryption Failed: Plaintext Wrong!\n");

    if( alen ) {
        ptr = ADEC_FUNC(aead)((void *)&gcm, iv, alen-1, a+1, len, c, x, 16, t);
        if( ptr ) printf("Decryption Errornously Secceeded!\n");
    }

    printf("Test Over\n");
    
    return 0;
}
