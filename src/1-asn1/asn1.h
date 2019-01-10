/* DannyNiu/NJF, 2018-01-08. Public Domain. */

#ifndef MySuiteA_asn1_h
#define MySuiteA_asn1_h 1

#include "../mysuitea-common.h"

typedef struct asn1_term asn1_term_t;

struct asn1_term {
    // 0-3: standard defined.
    // 256: expects ANY/CHOICE when parsing. 
    short               class;

    // primitive(0)/construted(1). 
    char                pc;

    // when tags don't match, 
    // 0: skips DER, 1: skips term. 
    char                optional;

    // As standardized. 
    int                 tag;

    // set `value' to NULL if discarding. 
    void                *value; // holds the run-time representation.

    union {
        uint8_t         *buf;
        uint8_t const   *ptr;
    }; // holds the DER-encoded serialization plus identifier and length octets.
    size_t              length_tlv;
    
    union {
        uint8_t         *buffer;
        uint8_t const   *content;
    }; // holds the DER-encoded serialization.
    size_t              length_content;

    // offset from the beginning of this structure,
    // to the referred asn1_term,
    // in subscript index.
    // 0 means null. 
    ptrdiff_t           next;
    ptrdiff_t           firstchild;
};

// Currently parsing of SET type (not SET OF type) is unsupported. 
int asn1_der_parse(
    asn1_term_t *restrict t,
    void const *restrict der,
    size_t len);

#endif /* MySuiteA_asn1_h */
