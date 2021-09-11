/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../2-hash/sha.h"

#include "../test-utils.c.h"
#include "../2-xof/gimli-xof.h"
static gimli_xof_t gx;

#define NBITS 768
#define SSLEN 16

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;
    
    size_t po_size = PKCS1_PADDING_ORACLES_CTX_SIZE(cSHA256, cSHA256, 32);
    size_t priv_size = RSA_PRIVATE_CONTEXT_SIZE(NBITS, 2);
    size_t pub_size;

    RSAES_OAEP_Dec_Context_t *dex = malloc(
        sizeof(*dex) + po_size + priv_size);

    if( !dex )
    {
        perror("malloc 1");
        exit(EXIT_FAILURE);
    }

    dex->offset_padding_oracle = sizeof(*dex);
    dex->offset_rsa_privctx = sizeof(*dex) + po_size;

    pkcs1_padding_oracles_base_t *pox =
        (void *)((uint8_t *)dex + dex->offset_padding_oracle);

    *pox = PKCS1_PADDING_ORACLES_BASE_INIT(xSHA256, xSHA256, 32);

    RSA_Private_Context_t *rsa_privx =
        (void *)((uint8_t *)dex + dex->offset_rsa_privctx);
    
    RSA_Private_Param_t rsa_params = RSA_PRIVATE_PARAM_ENTUPLE(NBITS, 2);

    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( argc >= 2 )
        Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
    Gimli_XOF_Final(&gx);

    lret = rsa_keygen(
        rsa_privx, &rsa_params,
        (GenFunc_t)Gimli_XOF_Read, &gx);

    if( !lret )
    {
        perror("MySuiteA rsa_keygen 1");
        exit(EXIT_FAILURE);
    }

    void *copy;

    // Debug: dump private key.
    lret = ber_tlv_encode_RSAPrivateKey(1, NULL, 0, rsa_privx, NULL);
    copy = malloc(lret);
    FILE *fp = fopen("rsa-priv-768.key", "wb");
    ber_tlv_encode_RSAPrivateKey(2, copy, lret, rsa_privx, NULL);
    fwrite(copy, 1, lret, fp);
    fclose(fp);
    free(copy); copy = NULL;

    lret = ber_tlv_encode_RSAPublicKey(1, NULL, 0, rsa_privx, NULL);
    copy = malloc(lret);

    if( !copy )
    {
        perror("malloc 2");
        exit(EXIT_FAILURE);
    }

    ber_tlv_encode_RSAPublicKey(2, copy, lret, rsa_privx, NULL);

    pub_size = ber_tlv_decode_RSAPublicKey(1, copy, lret, NULL, NULL);
    RSAES_OAEP_Enc_Context_t *enx = malloc(
        sizeof(*enx) + po_size + pub_size);

    enx->offset_padding_oracle = sizeof(*enx);
    enx->offset_rsa_pubctx = sizeof(*enx) + po_size;

    RSA_Public_Context_t *rsa_pubx =
        (void *)((uint8_t *)enx + enx->offset_rsa_pubctx);
    ber_tlv_decode_RSAPublicKey(2, copy, lret, rsa_pubx, NULL);

    pox = (void *)((uint8_t *)enx + enx->offset_padding_oracle);
    *pox = PKCS1_PADDING_ORACLES_BASE_INIT(xSHA256, xSHA256, 32);

    free(copy);
    copy = NULL;
    int failures = 0;
    int testcount = 100;

    for(int i=0; i<testcount; i++)
    {
        size_t sslen = SSLEN;
        void *ss1 = malloc(sslen);
        void *ss2 = malloc(sslen);

        RSAES_OAEP_Enc(enx, ss1, &sslen, (GenFunc_t)Gimli_XOF_Read, &gx);
        RSAES_OAEP_Encode_Ciphertext(enx, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        RSAES_OAEP_Encode_Ciphertext(enx, copy, &size);        
        RSAES_OAEP_Decode_Ciphertext(dex, copy, size);
        
        lret = (IntPtr)RSAES_OAEP_Dec(dex, ss2, &sslen);
        if( memcmp(ss1, ss2, sslen) || !lret )
        {
            printf("Cipher Failure, %zd, %ld\n", sslen, (long)lret);
            failures ++;
        }
    }

    printf("%d of %d failed tests\n", failures, testcount);
    return 0;
}
