/* DannyNiu/NJF, 2021-10-30. Public Domain. */

#define PKC_KeyAlgo iPKCS1_KeyCodec

#define PKC_Keygen                                      \
    ((PKKeygenFunc_t)(PKC_KeyAlgo(PKKeygenFunc)))

#define PKC_Encode_PrivateKey                           \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPrivkeyEncoder)))

#define PKC_Decode_PrivateKey                           \
    ((PKKeyDecoder_t)(PKC_KeyAlgo(PKPrivkeyDecoder)))

#define PKC_Export_PublicKey                            \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPubkeyExporter)))

#define PKC_Encode_PublicKey                            \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPubkeyEncoder)))

#define PKC_Decode_PublicKey                            \
    ((PKKeyDecoder_t)(PKC_KeyAlgo(PKPubkeyDecoder)))

PKCS1_RSA_Param_t params = {
    [0] = { .info = iSHA256, .param = NULL, },
    [1] = { .info = iSHA256, .param = NULL, },
    [2] = { .info = NULL, .aux = 32, },
    [3] = { .info = NULL, .aux = NBITS, },
    [4] = { .info = NULL, .aux = 2, },
};

PKCS1_Priv_Ctx_Hdr_t *kgx = NULL;

Gimli_XOF_Init(&gx);
Gimli_XOF_Write(&gx, "Hello World!", 12);
if( argc >= 2 )
    Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
Gimli_XOF_Final(&gx);

lret = PKC_Keygen(NULL, params, NULL, NULL);
kgx = my_alloc("kgx", lret);
size = lret;

if( !kgx )
{
    perror("malloc 1");
    exit(EXIT_FAILURE);
}
    
lret = PKC_Keygen(kgx, params, (GenFunc_t)Gimli_XOF_Read, &gx);

if( !lret )
{
    perror("MySuiteA RSA Key Generation 1");
    exit(EXIT_FAILURE);
}
else printf("keygen.lret: %lx, %p\n", lret, kgx);

PKCS1_Priv_Ctx_Hdr_t *dex = NULL;
void *copy;

// recoding private key.
lret = PKC_Encode_PrivateKey(kgx, NULL, 0, params);
copy = my_alloc("dex", lret);
PKC_Encode_PrivateKey(kgx, copy, lret, params);

FILE *fp = fopen("./rsa-priv-768.key", "wb"); // in "bin/"
fwrite(copy, 1, lret, fp);
fclose(fp);

size = lret;
lret = PKC_Decode_PrivateKey(NULL, copy, size, params);
if( lret < 0 )
{
    perror("privkey-decode 1");
    exit(EXIT_FAILURE);
}
dex = my_alloc("dex", lret);
PKC_Decode_PrivateKey(dex, copy, size, params);
free(copy); copy = NULL;

// transfer public key to encryption working context.
lret = PKC_Export_PublicKey(dex, NULL, 0, NULL);
copy = my_alloc("pubkey.der", lret);

if( !copy )
{
    perror("malloc 2");
    exit(EXIT_FAILURE);
}

PKC_Export_PublicKey(kgx, copy, lret, NULL);

PKCS1_Pub_Ctx_Hdr_t *enx = NULL;
size = lret;
lret = PKC_Decode_PublicKey(NULL, copy, size, params);
if( lret < 0 )
{
    perror("pubkey-decode 1");
    exit(EXIT_FAILURE);
}
enx = my_alloc("enx", lret);
PKC_Decode_PublicKey(enx, copy, size, params);
free(copy); copy = NULL;
