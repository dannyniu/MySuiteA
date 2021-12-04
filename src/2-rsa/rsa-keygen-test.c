/* DannyNiu/NJF, 2021-02-16. Public Domain. */

#include "rsa.h"
#include "rsa-codec-der.h"
#include "../2-xof/gimli-xof.h"

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static gimli_xof_t gx;

#define DUMP_CONTEXT_WORDS 1

void dump_ctx_words(const uint32_t *ctx, size_t size)
{
    if( !ctx ) return;
#if DUMP_CONTEXT_WORDS
    for(size_t i=0; i*4<size; i++)
    {
        printf(
            "%08x%c", ctx[i],
            (4 - i % 4 == 1) ? '\n' : ' ');
    }
#endif /* DUMP_CONTEXT_WORDS */
}

int main(int argc, char *argv[])
{
    size_t size, len;
    uint8_t *der1, *der2;
    RSA_Priv_Ctx_Hdr_t *ctx, *ctx2;
    RSA_Priv_Param_t p_rsa = {
        [0].aux = 960, // modulus bits.
        [1].aux = 3, // primes count
    };
    
    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( argc >= 2 )
        Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
    Gimli_XOF_Final(&gx);

    // Experiment 1: RSA Key Generation.
    size = rsa_keygen(NULL, p_rsa, NULL, NULL);
    printf("sizeof(ctx-priv): %zu\n", size);
    
    ctx = malloc(size);
    rsa_keygen(ctx, p_rsa, (GenFunc_t)Gimli_XOF_Read, &gx);

    dump_ctx_words((void *)ctx, size);

    // Experiment 2: Encoding the Generated Private Key.
    len = ber_tlv_encode_RSAPrivateKey(ctx, NULL, 0);
    printf("sizeof(der-priv): %zu\n", len);

    der1 = malloc(len);
    ber_tlv_encode_RSAPrivateKey(ctx, der1, len);

    // Experiment 3: Decode and Encode and Compare.

    size = ber_tlv_decode_RSAPrivateKey(NULL, der1, len);
    ctx2 = malloc(size);
    ber_tlv_decode_RSAPrivateKey(ctx2, der1, len);

    size = ber_tlv_encode_RSAPrivateKey(ctx, NULL, 0);
    printf("sizeof(der-priv): %zu\n", size);

    der2 = malloc(size);
    ber_tlv_encode_RSAPrivateKey(ctx, der2, size);

    // -- Result of the Compare --

    if( len != size )
        printf("Length Different\n");
    
    else if( memcmp(der1, der2, len) )
        printf("Encoding Different\n");
    
    return 0;
}
