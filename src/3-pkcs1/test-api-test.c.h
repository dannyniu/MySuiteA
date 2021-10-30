/* DannyNiu/NJF, 2021-10-30. Public Domain. */

PKCS1_Priv_Param_t params = {
    [0] = { .info = iSHA256, .param = NULL, },
    [1] = { .info = iSHA256, .param = NULL, },
    [2] = { .info = NULL, .aux = 32, },
    [3] = { .info = NULL, .aux = NBITS, },
    [4] = { .info = NULL, .aux = 2, },
};

PKCS1_Codec_Aux_t ap = {
    .aux_po = {
        [0] = { .info = iSHA256, .param = NULL, },
        [1] = { .info = iSHA256, .param = NULL, },
        [2] = { .info = NULL, .aux = 32, },
    },
};
    
PKCS1_Priv_Ctx_Hdr_t *kgx = NULL;

Gimli_XOF_Init(&gx);
Gimli_XOF_Write(&gx, "Hello World!", 12);
if( argc >= 2 )
    Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
Gimli_XOF_Final(&gx);

lret = PKCS1_Keygen(NULL, params, NULL, NULL);
kgx = my_alloc("kgx", lret);

if( !kgx )
{
    perror("malloc 1");
    exit(EXIT_FAILURE);
}
    
lret = PKCS1_Keygen(kgx, params, (GenFunc_t)Gimli_XOF_Read, &gx);

if( !lret )
{
    perror("MySuiteA RSA Key Generation 1");
    exit(EXIT_FAILURE);
}
else printf("keygen.lret: %lx, %p\n", lret, kgx);

PKCS1_Priv_Ctx_Hdr_t *dex = NULL;
void *copy;

// recoding private key.
lret = PKCS1_Encode_RSAPrivateKey(1, NULL, 0, kgx, &ap);
copy = malloc(lret);
PKCS1_Encode_RSAPrivateKey(2, copy, lret, kgx, NULL);

FILE *fp = fopen("./rsa-priv-768.key", "wb"); // in "bin/"
fwrite(copy, 1, lret, fp);
fclose(fp);

size = lret;
lret = PKCS1_Decode_RSAPrivateKey(1, copy, size, NULL, &ap);
if( lret < 0 )
{
    perror("privkey-decode 1");
    exit(EXIT_FAILURE);
}
dex = my_alloc("dex", lret);
PKCS1_Decode_RSAPrivateKey(2, copy, size, dex, &ap);
free(copy); copy = NULL;

// transfer public key to encryption working context.
lret = PKCS1_Encode_RSAPublicKey(1, NULL, 0, dex, NULL);
copy = my_alloc("pubkey.der", lret);

if( !copy )
{
    perror("malloc 2");
    exit(EXIT_FAILURE);
}

PKCS1_Encode_RSAPublicKey(2, copy, lret, kgx, NULL);

PKCS1_Pub_Ctx_Hdr_t *enx = NULL;
size = lret;
lret = PKCS1_Decode_RSAPublicKey(1, copy, size, NULL, &ap);
if( lret < 0 )
{
    perror("pubkey-decode 1");
    exit(EXIT_FAILURE);
}
enx = my_alloc("enx", lret);
PKCS1_Decode_RSAPublicKey(2, copy, size, enx, &ap);
free(copy); copy = NULL;
