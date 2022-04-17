/* DannyNiu/NJF, 2019-06-06. Public Domain. */

#ifndef MySuiteA_largeint_h
#define MySuiteA_largeint_h 1

#include "../mysuitea-common.h"

struct intdesc
{
    // word count,
    // most-significant byte first,
    // most-significant word first.
    unsigned len; // Recommended maximum: 256
    unsigned short msb, msw;

    // data pointer.
    union {
        uint32_t *p;
        uint32_t const* c;
    };
};

struct intview
{
    unsigned base, len;
    struct intdesc intd;
};

uint32_t intdesc_getword32(const struct intdesc intd, unsigned i);
void     intdesc_setword32(const struct intdesc intd, unsigned i, uint32_t x);
uint32_t intview_getword32(const struct intview intv, unsigned i);
void     intview_setword32(const struct intview intv, unsigned i, uint32_t x);

#define getword32(s, i)                                 \
    _Generic(s,                                         \
             struct intdesc: intdesc_getword32,         \
             struct intview: intview_getword32 )(s, i)

#define setword32(s, i, x)                                      \
    _Generic(s,                                                 \
             struct intdesc: intdesc_setword32,                 \
             struct intview: intview_setword32 )(s, i, x)

void li_add(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b);

void li_sub(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b);

void li_mul(
    const struct intdesc out,
    const struct intdesc a,
    const struct intdesc b);

void li_div(
    const struct intdesc quo,
    const struct intdesc rem,
    const struct intdesc a,
    const struct intdesc b);

#endif /* MySuiteA_largeint_h */
