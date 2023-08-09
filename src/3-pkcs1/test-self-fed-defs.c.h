/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#define PKC_Keygen PKCS1_Keygen

#define PKC_Encode_PrivateKey PKCS1_Encode_RSAPrivateKey
#define PKC_Decode_PrivateKey PKCS1_Decode_RSAPrivateKey
#define PKC_Export_PublicKey PKCS1_Export_RSAPublicKey
#define PKC_Encode_PublicKey PKCS1_Encode_RSAPublicKey
#define PKC_Decode_PublicKey PKCS1_Decode_RSAPublicKey

#define NBITS 768

PKCS1_RSA_Param_t params = {
    [0] = { .info = iSHA256, .param = NULL, },
    [1] = { .info = iSHA256, .param = NULL, },
    [2] = { .info = NULL, .aux = NBITS, },
    [3] = { .info = NULL, .aux = 2, },
};

#define kgx_decl PKCS1_PRIV_CTX_T(cSHA256,cSHA256,NBITS,2)
#define enx_decl PKCS1_PUB_CTX_T(cSHA256,cSHA256,NBITS,2)

#define kgx_init {                              \
        .header = PKCS1_PRIV_CTX_INIT(          \
            params[0].info, params[1].info,     \
            params[2].aux, params[3].aux), }

#define enx_init {                              \
        .header = PKCS1_PUB_CTX_INIT(           \
            params[0].info, params[1].info,     \
            params[2].aux, params[3].aux), }
