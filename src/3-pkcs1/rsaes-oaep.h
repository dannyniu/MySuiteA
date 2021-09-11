/* DannyNiu/NJF, 2021-09-10. Public Domain. */

#include "../2-rsa/rsa.h"
#include "../2-rsa/pkcs1-padding.h"

typedef struct {
    uint32_t    offset_padding_oracle;
    uint32_t    offset_rsa_privctx;
} RSAES_OAEP_Dec_Context_t;

// returns x on success and NULL on failure.
void *RSAES_OAEP_Decode_Ciphertext(
    RSAES_OAEP_Dec_Context_t *restrict x,
    void *restrict ct, size_t ctlen);

// returns x on success and NULL on failure.
// if ss is NULL, *sslen is set to its length.
void *RSAES_OAEP_Dec(
    RSAES_OAEP_Dec_Context_t *restrict x,
    void *restrict ss, size_t *restrict sslen);

typedef struct {
    uint32_t    offset_padding_oracle;
    uint32_t    offset_rsa_pubctx;
} RSAES_OAEP_Enc_Context_t;

// returns ct on success and NULL on failure.
// if ct is NULL, *ctlen is set to its length.
void *RSAES_OAEP_Encode_Ciphertext(
    RSAES_OAEP_Enc_Context_t *restrict x,
    void *restrict ct, size_t *ctlen);

// returns ss on success and NULL on failure.
// by convention, if ss is NULL, *sslen is set to its length.
// however, because RSA accepts arbitrary-length message as input,
// the RSA-OAEP encrypt call will not change its value.
void *RSAES_OAEP_Enc(
    RSAES_OAEP_Enc_Context_t *restrict x,
    void *restrict ss, size_t *restrict sslen,
    GenFunc_t prng_gen, void *restrict prng);
