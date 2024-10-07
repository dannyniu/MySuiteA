/* DannyNiu/NJF, 2022-02-25. Public Domain. */

// Expects: PKC_KeyAlgo

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

void *kgx = NULL;

PKC_PRNG_Init(
    argc>=2 ? argv[1] : NULL,
    argc>=2 ? strlen(argv[1]) : 0);

lret = PKC_Keygen(NULL, params, NULL, NULL);
kgx = my_alloc("kgx", lret);
size = lret;

if( !kgx )
{
    perror("malloc 1");
    exit(EXIT_FAILURE);
}

lret = PKC_Keygen(kgx, params, PKC_PRNG_Gen, prng);

if( !lret )
{
    perror("Key Generation 1");
    exit(EXIT_FAILURE);
}
else printf("keygen.lret: %lx, %p\n", lret, kgx);

void *dex = NULL;
void *copy;

// recoding private key.
lret = PKC_Encode_PrivateKey(kgx, NULL, 0, params);
copy = my_alloc("dex", lret);
PKC_Encode_PrivateKey(kgx, copy, lret, params);

FILE *fp = fopen("./privkey", "wb"); // in "auto/"
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
copy = my_alloc("pubkey.bin", lret);

if( !copy )
{
    perror("malloc 2");
    exit(EXIT_FAILURE);
}

PKC_Export_PublicKey(kgx, copy, lret, NULL);

void *enx = NULL;
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
