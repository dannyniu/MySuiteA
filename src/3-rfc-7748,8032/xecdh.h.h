/* DannyNiu/NJF, 2022-04-28. Public Domain. */

#include "rfc-7748.h"

#define XECDH_Keygen glue(XECDH,_Keygen)
#define XECDH_Encode_PrivateKey glue(XECDH,_Encode_PrivateKey)
#define XECDH_Decode_PrivateKey glue(XECDH,_Decode_PrivateKey)
#define XECDH_Export_PublicKey glue(XECDH,_Encode_PublicKey)
#define XECDH_Encode_PublicKey glue(XECDH,_Encode_PublicKey)
#define XECDH_Decode_PublicKey glue(XECDH,_Decode_PublicKey)
#define XECDH_Enc glue(XECDH,_Enc)
#define XECDH_Dec glue(XECDH,_Dec)
#define XECDH_Encode_Ciphertext glue(XECDH,_Encode_Ciphertext)
#define XECDH_Decode_Ciphertext glue(XECDH,_Decode_Ciphertext)

IntPtr XECDH_Keygen(
    XECDH_Ctx_Hdr_t *restrict x,
    CryptoParam_t *restrict param,
    GenFunc_t prng_gen, void *restrict prng);

IntPtr XECDH_Encode_PrivateKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr XECDH_Decode_PrivateKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr XECDH_Encode_PublicKey(
    void const *any, void *enc, size_t enclen, CryptoParam_t *restrict param);

IntPtr XECDH_Decode_PublicKey(
    void *any, const void *enc, size_t enclen, CryptoParam_t *restrict param);

void *XECDH_Enc(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);

void *XECDH_Dec(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

void *XECDH_Encode_Ciphertext(
    XECDH_Ctx_Hdr_t *restrict x,
    void *restrict ct, size_t *ctlen);

void *XECDH_Decode_Ciphertext(
    XECDH_Ctx_Hdr_t *restrict x,
    void const *restrict ct, size_t ctlen);

#undef XECDH_Keygen
#undef XECDH_Encode_PrivateKey
#undef XECDH_Decode_PrivateKey
#undef XECDH_Export_PublicKey
#undef XECDH_Encode_PublicKey
#undef XECDH_Decode_PublicKey
#undef XECDH_Enc
#undef XECDH_Dec
#undef XECDH_Encode_Ciphertext
#undef XECDH_Decode_Ciphertext
