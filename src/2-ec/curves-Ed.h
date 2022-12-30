/* DannyNiu/NJF, 2022-05-05. Public Domain. */

#ifndef MySuiteA_ecc_curves_Ed_h
#define MySuiteA_ecc_curves_Ed_h 1

#include "ecEd.h"

extern const ecEd_curve_t *CurveEd25519;
extern const ecEd_curve_t *CurveEd448;

#define cCurveEd25519(q) cCurveEd(q,256)
#define cCurveEd448(q) cCurveEd(q,448)

#define xCurveEd25519(q) xCurveEd(q,256,CurveEd25519)
#define xCurveEd448(q) xCurveEd(q,448,CurveEd448)

IntPtr iCurveEd25519(int q);
IntPtr iCurveEd448(int q);

#endif /* MySuiteA_ecc_curves_Ed_h */
