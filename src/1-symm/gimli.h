/* DannyNiu/NJF, 2018-04-20. Public Domain. */

#ifndef MySuiteA_gimli_h
#define MySuiteA_gimli_h 1

// 2021-05-16:
// Gimli have had critical cryptanalysis in [1] and [2],
// and had been eliminated from NIST LWC project in the
// final round. However, the implementation is retained
// in the same vein as been with SHA-1.
//
// References:
// [1]:
// New results on Gimli: full-permutation
// distinguishers and improved collisions
// A.F.Gutierrez et.al.
// https://eprint.iacr.org/2020/744
//
// [2]:
// Exploiting Weak Diffusion of Gimli: Improved
// Distinguishers and Preimage Attacks
// Fukang Liu et.al.
// https://doi.org/10.46586/tosc.v2021.i1.185-216

#include "../mysuitea-common.h"

void Gimli_Permute(void const *in, void *out);

#define cGimli(q) ( q==blockBytes ? 48 : 0 )

#define xGimli(q) (                                     \
        q==PermuteFunc ? (IntPtr)Gimli_Permute :        \
        cGimli(q) )

IntPtr iGimli(int q);

#endif /* MySuiteA_gimli_h */
