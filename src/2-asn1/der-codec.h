/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#ifndef MySuiteA_der_codec_h
#define MySuiteA_der_codec_h 1

#include "../mysuitea-common.h"
#include "../1-integers/vlong.h"

// 2021-02-12:
// MySuiteA internally represent BER tags and lengths as 32-bit integers.
// For tags, the sign bit is set, and the 2nd and 3rd most significant bit
// is allocated to represent tag types. For lengths, the sign bit is clear.

#define BER_TLV_TAG_MAX         UINT32_C(0x0fffffff)
#define BER_TLV_TAG_UNI(x) (x | UINT32_C(0x80000000)) // universal tag,
#define BER_TLV_TAG_APP(x) (x | UINT32_C(0x90000000)) // application tag,
#define BER_TLV_TAG_CTX(x) (x | UINT32_C(0xA0000000)) // context-specific tag,
#define BER_TLV_TAG_PRI(x) (x | UINT32_C(0xB0000000)) // private tag.
#define BER_TLV_LENGTH(x)  (x & UINT32_C(0x7FFFFFFF))

// 2021-02-14:
// For nomenclature consistency:
// 1. a function contains the words encode/decode in its name,
// 2. a source code files contains the parser/writer in its name.

uint32_t ber_get_tag(const uint8_t **buf, size_t *len);
uint32_t ber_get_len(const uint8_t **buf, size_t *len);
int ber_get_hdr(
    const uint8_t **ptr, size_t *remain,
    uint32_t *tag, uint32_t *len);

// stacks are pre-allocated using estimated values returned from the
// 1st pass invocation of ``ber_tlv_encoding_func'' functions.
uint8_t *ber_push_len(uint8_t **stack, uint32_t val);
uint8_t *ber_push_tag(uint8_t **stack, uint32_t val, int pc);
void *ber_util_splice_insert(
    void *buf,        size_t len1,
    ptrdiff_t offset, size_t len2);

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
// parameter is specific to individual decoding and encoding
// functions, and should be documented by them.

#define BER_TLV_DECODING_FUNC_PARAMS                    \
    int pass, const uint8_t *enc, uint32_t enclen,      \
    void *any, void *aux

#define BER_TLV_ENCODING_FUNC_PARAMS                    \
    int pass, uint8_t *enc, uint32_t enclen,            \
    const void *any, void *aux

typedef int32_t (*ber_tlv_decoding_func)(BER_TLV_DECODING_FUNC_PARAMS);
typedef int32_t (*ber_tlv_encoding_func)(BER_TLV_ENCODING_FUNC_PARAMS);

// [ber-int-err-chk:2021-02-13].
int32_t ber_tlv_decode_integer(BER_TLV_DECODING_FUNC_PARAMS);

#endif /* MySuiteA_der_parse_h */
