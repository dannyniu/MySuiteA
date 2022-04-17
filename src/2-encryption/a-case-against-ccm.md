2022-04-17: There was no CCM in MySuiteA
========================================

## 2021-07-26: There is no CCM in MySuiteA

Much of the criticisms of CCM is available in "A Critique of CCM" by
P. Rogway, D. Wagner published in Feb 2003, available at:
https://web.cs.ucdavis.edu/~rogaway/papers/ccm.pdf

Here's a summary of reasons I omitted it in MySuiteA.

While I can find a clean way to deal with the 1.) the undue implementation
burdon of variable-length encoding of lengths, 2.) ensuring the security
under "releasing unverified plaintext" (RUP) model at suboptimal efficiency,
CCM's MAC Tag value calculation is dependent on the tag's length, making
it incompatible with the tag truncation practice in the current MySuiteA
AEAD interfaces.

In MySuiteA, AEAD interfaces produce and verify tags of arbitrary length by
1.) truncating the MAC Tag when the desired length is smaller, and 2.) zero-
extending the tag when the desired length is larger. In CCM however, the
tag length is entrenched into the value of the tag. This leaves me with
2 options: 1.) fix an internal tag length and stick with existing MySuiteA
interfaces, 2.) establish an exception for CCM. Neither of which is acceptable.

Lastly it's not unprecedented to omit an algorithm due to its complexity -
Hash-DRBG had been omitted due to it having exception cases for
parameter values based on the hash function it's instantiated with
(and the parameter is NOT an intrisic property of the hash function).

The only place where CCM is the only viable encryption algorithm I'm aware of
is IEEE-802.11i WiFi encryption. Most of the IETF protocols I'm aware of have
the option to use GCM.

MySuiteA is written to illustrate layering of cryptographic primitives and to
experiment with cryptographic component agility, if there is actually real
desire from users of this library to support CCM, I may reconsider then.
