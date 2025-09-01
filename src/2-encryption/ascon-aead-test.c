/* DannyNiu/NJF, 2025-09-01. Public Domain. */

#include "ascon-aead.h"

iCryptoObj_t AsconAEAD;

#define aead AsconAEAD
#define mode ((tCryptoObj_t)0)
#define bc ((iCryptoObj_t)0)

#include "encryption-test.c.h"

int main(int argc, char *argv[])
{
    AsconAEAD = iAscon_AEAD128;
    if( strlen((argv+1)[3]) == 64 )
        AsconAEAD = iAscon_AEAD256;

    if( strcmp(argv[1], "enc") == 0 )
        return Encrypt(argc-1, argv+1);

    if( strcmp(argv[1], "dec") == 0 )
        return Decrypt(argc-1, argv+1);

    return 2;
}
