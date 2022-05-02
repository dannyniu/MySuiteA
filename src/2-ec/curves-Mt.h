/* DannyNiu/NJF, 2022-05-02. Public Domain. */

#ifndef MySuiteA_ecc_curves_Mt_h
#define MySuiteA_ecc_curves_Mt_h 1

#include "ecMt.h"

extern const ecMt_curve_t *Curve25519;
extern const ecMt_curve_t *Curve448;

#define cX25519(q) (                            \
        q==ecMt_BitsModulus ? 255 :             \
        0)

#define xX25519(q) (                                    \
        q==ecMt_PtrCurveDef ? (IntPtr)Curve25519 :      \
        cX25519(q))

#define cX448(q) (                              \
        q==ecMt_BitsModulus ? 448 :             \
        0)

#define xX448(q) (                                      \
        q==ecMt_PtrCurveDef ? (IntPtr)Curve448 :        \
        cX448(q))

IntPtr iX25519(int q);
IntPtr  iX448(int q);

#endif /* MySuiteA_ecc_curves_Mt_h */
