/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#ifndef MySuiteA_der_codec_h
#define MySuiteA_der_codec_h 1

#include "../mysuitea-common.h"

// This header needs the vlong types,
// the implementation needs the 'topbit' function.
#include "../1-integers/vlong-dat.h"

// 2021-02-12:
// MySuiteA internally represent BER tags as 32-bit integers and lengths as
// ``size_t''. For tags, the most-significant is set, and the 2nd and 3rd
// most significant bit is allocated to represent tag types.
//
// 2021-11-19:
// BER TLV lengths are changed to be represented by ``size_t''. The above note
// had been amended accordingly.

#define BER_TLV_TAG_MAX         UINT32_C(0x0fffffff) // also a valid mask.
#define BER_TLV_TAG_UNI(x) (x | UINT32_C(0x80000000)) // universal tag,
#define BER_TLV_TAG_APP(x) (x | UINT32_C(0xA0000000)) // application tag,
#define BER_TLV_TAG_CTX(x) (x | UINT32_C(0xC0000000)) // context-specific tag,
#define BER_TLV_TAG_PRI(x) (x | UINT32_C(0xE0000000)) // private tag.

// 2021-02-14:
// For nomenclature consistency:
// 1. a function contains the words encode/decode (and export) in its name,
// 2. a source code files contains the parser/writer (and export) in its name.

uint32_t ber_get_tag(const uint8_t **buf, size_t *len);
size_t   ber_get_len(const uint8_t **buf, size_t *len);
int ber_get_hdr(
    const uint8_t **ptr, size_t *remain,
    uint32_t *tag, size_t *len);

// stacks are pre-allocated using estimated values returned from the
// 1st pass invocation of ``ber_tlv_encoding_func'' functions.
size_t ber_push_len(uint8_t **stack, size_t val);
size_t ber_push_tag(uint8_t **stack, uint32_t val, int pc);
void *ber_util_splice_insert(
    void *buf,        size_t len1,
    ptrdiff_t offset, size_t len2);

//
// A ``ber_tlv_{de,en}coding_func'' have 2 passes,
//
// - In pass 1, they returns the estimated size of memory required for holding:
//   * a working context decoded from a DER-encoded object,
//   * DER-encoding of the working variables.
//
//   On error, it returns -1, possibly propagated from
//   nested calls.
//
// - In pass 2, the functions:
//   * decodes the DER-encoded object into the working context buffer,
//   * encodes the DER representation of the working variables into a buffer.
//   The buffer is allocated using the estimate from pass 1.
//
//   the function returns the same value as in pass 1.
//
// To enter pass 1 in encoding (decoding) function, ``enc'' (any) should be
// specified as NULL, and (in decoding functions) ``enclen'' should be 0
// (in the decoding functions, ``enclen'' is ignored for now, but values
// other than 0 should be considered as reserved).
//
// To enter pass 2, both ``any'' and ``enc'' should be specified, and
// ``enclen'' should be the size of the buffer allocated for ``enc''.

#define BER_TLV_DECODING_FUNC_PARAMS                    \
    void *any, const uint8_t *enc, size_t enclen

#define BER_TLV_ENCODING_FUNC_PARAMS                    \
    void const *any, uint8_t *enc, size_t enclen

typedef IntPtr (*ber_tlv_decoding_func)(BER_TLV_DECODING_FUNC_PARAMS);
typedef IntPtr (*ber_tlv_encoding_func)(BER_TLV_ENCODING_FUNC_PARAMS);

//
// 2021-04-17, late note:
// Because it requires handling length estimates, tagging, re-splicing, etc.
// it is more natural to write primitive value codec functions to work
// without caring for those, and let structure codec functions care for them.

// [ber-int-err-chk:2021-02-13].
IntPtr ber_tlv_decode_integer(BER_TLV_DECODING_FUNC_PARAMS);
IntPtr ber_tlv_encode_integer(BER_TLV_ENCODING_FUNC_PARAMS);

#endif /* MySuiteA_der_parse_h */
