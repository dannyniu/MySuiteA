/* DannyNiu/NJF, 2022-02-25. Public Domain. */

// Expects: PKC_Keygen. PKC_{Encode,Decode,Export}_{Private,Public}Key.

kgx_decl kgx = kgx_init;

PKC_PRNG_Init(
    argc>=2 ? argv[1] : NULL,
    argc>=2 ? strlen(argv[1]) : 0);

lret = PKC_Keygen(&kgx.header, params, PKC_PRNG_Gen, prng);

if( !lret )
{
    perror("Key Generation 1");
    exit(EXIT_FAILURE);
}
else printf("keygen.lret: %lx, %p\n", lret, &kgx.header);

void *dex = &kgx.header;
void *copy;

// Debug: dump private key.
lret = PKC_Encode_PrivateKey(&kgx.header, NULL, 0, NULL);
copy = malloc(lret);
PKC_Encode_PrivateKey(&kgx.header, copy, lret, NULL);

FILE *fp = fopen("./privkey", "wb"); // in "bin/"
fwrite(copy, 1, lret, fp);
fclose(fp);
free(copy); copy = NULL;

// transfer public key to encryption working context.
lret = PKC_Export_PublicKey(&kgx.header, NULL, 0, NULL);
copy = my_alloc("pubkey.bin", lret);

if( !copy )
{
    perror("malloc 2");
    exit(EXIT_FAILURE);
}

PKC_Export_PublicKey(&kgx.header, copy, lret, NULL);

enx_decl enx = enx_init;

PKC_Decode_PublicKey(&enx.header, copy, lret, params);

free(copy);
copy = NULL;
