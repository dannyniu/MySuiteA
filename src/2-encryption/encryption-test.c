/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#include "chacha20-poly1305.h"
#include "gcm-aes.h"
#include "../test-utils.c.h"

static char line[128], word[128];
static uint8_t k[32], iv[12], a[32], p[1024], c[1024], s[16], t[16], x[1024];
static size_t len, alen;

static gcm_aes256_t gcm;

int main(int argc, char *argv[])
{
    int i;
    uint8_t *ptr = NULL, *tmp;
    size_t *acc = NULL;
    iCryptoObj_t aead = iGCM_AES128, bc = iAES128;
    tCryptoObj_t mode = tGCM;
    CryptoParam_t Bc;

    if( argc < 3 ) return 1;
    if( !strcmp(argv[1], "128") ) aead=iGCM_AES128, bc=iAES128, mode=tGCM;
    if( !strcmp(argv[1], "192") ) aead=iGCM_AES192, bc=iAES192, mode=tGCM;
    if( !strcmp(argv[1], "256") ) aead=iGCM_AES256, bc=iAES256, mode=tGCM;
    if( !strcmp(argv[1], "20") ) aead=iChaCha_AEAD, bc=NULL, mode=NULL;
    Bc.info = bc, Bc.aux = NULL;

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

    KINIT_FUNC(aead)(
        &gcm, k, KEY_BYTES(aead));
    AENC_FUNC(aead)(
        (void *)&gcm, iv, alen, a, len, p, x, 16, s);
    if( memcmp(s, t, 16) ) printf("Enc Fail: Tag Wrong!\n");
    if( memcmp(c, x, len) ) printf("Enc Fail: Ciphertext Wrong!\n");
    ptr = ADEC_FUNC(aead)(
        (void *)&gcm, iv, alen, a, len, c, x, 16, t);
    if( !ptr ) printf("Dec Errornously Returned FAIL\n");
    if( memcmp(p, x, len) ) printf("Dec Fail: Plaintext Wrong!\n");

    if( alen ) {
        ptr = ADEC_FUNC(aead)(
            (void *)&gcm, iv, alen-1, a+1, len, c, x, 16, t);
        if( ptr ) printf("Dec Errornously Secceeded!\n");
    }

    if( mode && bc )
    {
        ((PKInitFunc_t)mode(&Bc, KInitFunc))(
            &Bc, &gcm, k, mode(&Bc, keyBytes));
        ((AEncFunc_t)mode(&Bc, AEncFunc))(
            (void *)&gcm, iv, alen, a, len, p, x, 16, s);
        if( memcmp(s, t, 16) ) printf("Enc Fail: Tag Wrong!\n");
        if( memcmp(c, x, len) ) printf("Enc Fail: Ciphertext Wrong!\n");
        ptr = ((ADecFunc_t)mode(&Bc, ADecFunc))(
                   (void *)&gcm, iv, alen, a, len, c, x, 16, t);
        if( !ptr ) printf("Dec Errornously Returned FAIL\n");
        if( memcmp(p, x, len) ) printf("Dec Fail: Plaintext Wrong!\n");
        
        if( alen ) {
            ptr = ((ADecFunc_t)mode(&Bc, ADecFunc))(
                (void *)&gcm, iv, alen-1, a+1, len, c, x, 16, t);
            if( ptr ) printf("Dec Errornously Secceeded!\n");
        }

    }

    printf("Test Over\n");
    
    return 0;
}
