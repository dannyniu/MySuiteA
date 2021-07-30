/* DannyNiu/NJF, 2021-01-13. Public Domain. */

#ifndef MySuiteA_rsa_codec_der_h
#define MySuiteA_rsa_codec_der_h 1

#include "rsa.h"
#include "../2-asn1/der-codec.h"

//
// aux is not used for the private key encoding function.
int32_t ber_tlv_encode_RSAPrivateKey(BER_TLV_ENCODING_FUNC_PARAMS);

//
// ``*aux'' is a ``uint32_t'' holding the number of additional primes.
int32_t ber_tlv_decode_RSAPrivateKey(BER_TLV_DECODING_FUNC_PARAMS);

//
// aux is not used for the public key encoding function.
int32_t ber_tlv_encode_RSAPublicKey(BER_TLV_ENCODING_FUNC_PARAMS);

//
// aux is not used for the public key decoding function.
int32_t ber_tlv_decode_RSAPublicKey(BER_TLV_DECODING_FUNC_PARAMS);

#endif /* MySuiteA_rsa_codec_der_h */
