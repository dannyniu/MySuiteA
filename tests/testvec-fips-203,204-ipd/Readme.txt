October 2023

Note on the intermediate values for ML-KEM:
These test results were from an implementation of the
3 ML-KEMs in draft FIPS 203 with two specific changes:

1) The order of the input i and j to the XOF at
   step 6 in Algorithm 12 K-PKE.KeyGen() is switched.
2) The order of the input i and j to the XOF at
   step 6 in Algorithm 13 K-PKE.Encrypt() is switched.

In addition to the above, our implementation of Algorithm 13
uses a matrix variable "bHat" which is equal to the transpose
of the matrix "aHat", i.e., bHat[j,i]=aHat[i,j].  This is done
for convenience, and does not affect functionality.

Note on the intermediate values for ML-DSA. We recognize that
Table 2 of the draft FIPS 204 gives incorrect values for the
sizes of the signature and private key. In addition, we note
that the incorrect signature length is also reflected in the
output description in Algorithm 2 and the input description
in Algorithm 3 (both in draft FIPS 204). The lengths of signatures
and private keys in this Intermediate Values document are not
consistent with these, but rather with what would be expected
from following the steps of the pseudocode in draft FIPS 204.

In addition, ExpandMask (Algorithm 28) pulls bits from the
SHAKE bitstream off the front, rather than rc+1 bits further
in the bitstream.

2023-11-17, notes from MySuiteA developer:
This README file had been edited to fit texts in 80 columns.
example files are edited to leave only externally visible
variables remain to achieve a simplified test driver.

2023-11-19, notes from MySuiteA developer:
ML-KEM example values for key generation has some error with
the initial seeds ''z'' and ''d''. Testing of key generation
of BothML-KEM *And* ML-DSA are postponed for investigations.
