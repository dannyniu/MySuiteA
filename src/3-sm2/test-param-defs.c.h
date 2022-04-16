/* DannyNiu/NJF, 2022-02-26. Public Domain. */

#define iTestCurve glue(i_,curveSM2)
#define xTestCurve glue(x_,curveSM2)
#define cTestCurve glue(c_,curveSM2)
/*

// 2022-04-16 T 23:07
// Right now, it can be determined that the fault is with
// the implementation of the underlaying curve - curveSM2.
// Come back and debug tomorrow.
#define iTestCurve glue(i_,secp256r1)
#define xTestCurve glue(x_,secp256r1)
#define cTestCurve glue(c_,secp256r1)*/

#define iTestHash glue(i,SM3)
#define xTestHash glue(x,SM3)
#define cTestHash glue(c,SM3)
