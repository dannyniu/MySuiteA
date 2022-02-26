/* DannyNiu/NJF, 2022-02-26. Public Domain. */

#define iTestCurve glue(i_,TestCurve)
#define xTestCurve glue(x_,TestCurve)
#define cTestCurve glue(c_,TestCurve)

#ifdef TestHash
#define iTestHash glue(i,TestHash)
#define xTestHash glue(x,TestHash)
#define cTestHash glue(c,TestHash)
#endif /* TestHash */
