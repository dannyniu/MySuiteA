/* DannyNiu/NJF, 2021-10-30. Public Domain. */

PKCS1_RSA_Param_t params = {
    [0] = { .info = iSHA256, .param = NULL, },
    [1] = { .info = iSHA256, .param = NULL, },
    [2] = { .info = NULL, .aux = 32, },
    [3] = { .info = NULL, .aux = NBITS, },
    [4] = { .info = NULL, .aux = 2, },
};

PKCS1_PRIV_CTX_T(cSHA256,cSHA256,32,NBITS,2) kgx = {
    .header = PKCS1_PRIV_CTX_INIT(
        params[0].info, params[1].info, params[2].aux,
        params[3].aux, params[4].aux),
};

Gimli_XOF_Init(&gx);
Gimli_XOF_Write(&gx, "Hello World!", 12);
if( argc >= 2 )
    Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
Gimli_XOF_Final(&gx);

lret = PKCS1_Keygen(&kgx.header, params, (GenFunc_t)Gimli_XOF_Read, &gx);

if( !lret )
{
    perror("MySuiteA RSA Key Generation 1");
    exit(EXIT_FAILURE);
}
else printf("keygen.lret: %lx, %p\n", lret, &kgx.header);

PKCS1_Priv_Ctx_Hdr_t *dex = &kgx.header;
void *copy;

// Debug: dump private key.
lret = PKCS1_Encode_RSAPrivateKey(&kgx.header, NULL, 0, NULL);
copy = malloc(lret);
PKCS1_Encode_RSAPrivateKey(&kgx.header, copy, lret, NULL);

FILE *fp = fopen("./rsa-priv-768.key", "wb"); // in "bin/"
fwrite(copy, 1, lret, fp);
fclose(fp);
free(copy); copy = NULL;

// transfer public key to encryption working context.
lret = PKCS1_Export_RSAPublicKey(&kgx.header, NULL, 0, NULL);
copy = my_alloc("pubkey.der", lret);

if( !copy )
{
    perror("malloc 2");
    exit(EXIT_FAILURE);
}

PKCS1_Export_RSAPublicKey(&kgx.header, copy, lret, NULL);

PKCS1_PUB_CTX_T(cSHA256,cSHA256,32,NBITS,2) enx = {
    .header = PKCS1_PUB_CTX_INIT(
        params[0].info, params[1].info, params[2].aux,
        params[3].aux, params[4].aux),
};
    
PKCS1_Decode_RSAPublicKey(&enx.header, copy, lret, params);
    
uint32_t k =
    ((RSA_Pub_Ctx_Hdr_t *)(
        (uint8_t *)&enx.header +
        enx.header.offset_rsa_pubctx))->modulus_bits;
    
printf("Pubctx k: %u\n", k);

free(copy);
copy = NULL;
