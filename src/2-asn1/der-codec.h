/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#ifndef MySuiteA_der_codec_h
#define MySuiteA_der_codec_h 1

#include "../mysuitea-common.h"
#include "../1-integers/vlong.h"

// 2021-02-12:
// MySuiteA internally represent BER tags and lengths as 32-bit integers.
// For tags, the sign bit is set, and the 2nd and 3rd most significant bit
// is allocated to represent tag types. For lengths, the sign bit is clear.

#define BER_TLV_TAG_UNI(x) (x | UINT32_C(0x80000000)) // universal tag,
#define BER_TLV_TAG_APP(x) (x | UINT32_C(0x90000000)) // application tag,
#define BER_TLV_TAG_CTX(x) (x | UINT32_C(0xA0000000)) // context-specific tag,
#define BER_TLV_TAG_PRI(x) (x | UINT32_C(0xB0000000)) // private tag.
#define BER_TLV_LENGTH(x)  (x & UINT32_C(0x7FFFFFFF))

// 2021-02-14:
// For terminology consistency, we say:
// 1. decoding/encoding a BER/DER-encoded object,
// 2. a function is the parser/writer of some key format.

uint32_t ber_get_tag(const uint8_t **buf, size_t *len);
uint32_t ber_get_len(const uint8_t **buf, size_t *len);
int ber_get_hdr(
    const uint8_t **ptr, size_t *remain,
    uint32_t *tag, uint32_t *len);

//
// A ``ber_tlv_{de,en}coding_func'' has 2 passes,
//
// - In pass 1, it returns the estimated size of memory required for holding:
//   * a working context decoded from a DER-encoded object,
//   * DER-encoding of the working variables.
//
//   On error, it returns -1, possibly propagated from
//   nested calls.
//
// - In pass 2, the function:
//   * decodes the DER-encoded object into the working context buffer,
//   * encodes the DER representation of the working variables into a buffer.
//   The buffer is allocated using the estimate from pass 1.
//
//   the function returns the same value as in pass 1.
//
// - Pass 0 is reserved.
//
// The ``aux'' parameter holds working information that's
// passed from one pass to the next. The format of this
// parameter is specific to individual decoders, and should
// be documented by them.

#define BER_TLV_DECODING_FUNC_PARAMS                    \
    int pass, const uint8_t *src, uint32_t srclen,      \
    void *dst, void *aux

#define BER_TLV_ENCODING_FUNC_PARAMS                    \
    int pass, uint8_t *src, uint32_t srclen,            \
    const void *dst, void *aux

typedef int32_t (*ber_tlv_decoding_func)(BER_TLV_DECODING_FUNC_PARAMS);
typedef int32_t (*ber_tlv_encoding_func)(BER_TLV_ENCODING_FUNC_PARAMS);

// [ber-int-err-chk:2021-02-13].
int32_t ber_tlv_decode_integer(BER_TLV_DECODING_FUNC_PARAMS);

#endif /* MySuiteA_der_parse_h */
