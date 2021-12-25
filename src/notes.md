2018-02-08
==========

**2021-09-03 Update**: 
This file is being converted to Markdown format, this note is obsolete.

Markups used in note:

o. `$$$/$$$'

Usage: 1. Date the subarticle added. Three preceeding blank lines or a
          <form feed> would be required except for the first subarticle. 
       2. Subarticle top-level heading.

o. `$=/=$'

Usage: 1. Unnumbered item list item heading.

o. `::/::'

Usage: 1. Unlevelled inter-paragraph heading. 

---


2018-02-24
==========

In designing the API, it was decided that there will be no destructors for
primitives with no explicit `finalization' function. This is arbitrary.

---


2018-04-20
==========

**Focus of the suite / why isn't there public-key algorithms**

I want to demonstrate the layering of cryptographic primitives and constructs.

Symmetric-key cryptography is the easiest to work on because they are defined
to operate on and as operation of data directly;

Whereas public-key cryptography algorithms each have their own primitives that
aren't necessarily interoperable, work on abstract types that aren't directly
represented as octet string data (requires ASN.1 often), and often require
paying special attention to implementation pitfalls.

Anyway, this suite isn't supposed to replace existing mature products such as
LibreSSL, GnuTLS, etc. 

---


2020-01-20
==========

Infomation macros' prefix are changed from ''_i'' to ''c'' to avoid namespace
pollution with operating system implementations. ''c'' stands for "constants". 

---


2020-11-28
==========

Arbitrary engineering decisions are explained in comments in code
with the tag: [!A-E-D!]

---


2021-09-03a
===========

When "-Wgnu-folding-constant" warning is enabled, the compiler emits a warning
when nesting information macros in static type declarations. 

The proposed solution is to separate out function pointers into another macro
which will have the prefix "x" meaning "executable"; this new macro will
inherit the parameters in the "constants" macro by invoking them through
verbatim inclusion.

Instance "info" functions will switch to "x" macros for parameter values; 
users of instance macros will update their source of information.

The proposed change is realized as of 2021-09-04.

---


2021-09-03b
===========

It's decided that information macros for blockciphers, hash and XOF functions, 
and permutations shall not nest lower-level primitives. This restriction is 
added to:

1. ease the implementation of some higher level primitives (e.g. CTR-DRBG
   relies on block ciphers, and is built without provision for nested
   template instantiation; the same can be said for HMAC);

2. limit the nesting levels of information macros (e.g. PKCS#1 paddings of
   MySuiteA RSA implementations require 2 hash functions - 1 for message,
   1 for MGF. They would be able to share working context memory space if
   it's possible to calculate the maximum of 2 sizes, even though in most
   cases, they should be the same hash function. For more on this, see
   https://stackoverflow.com/q/68992622 ).

---


2021-12-24
==========

The queries for key-pair and ciphergram codec functions are separated from 
the queries for public-key algorithm so as to allow one implementation of a 
cryptosystem to interoperate with a variety of different applications that
use different data formats. The provision is made, but the availability of
codec functions for additional formats will depend on demand and on whether
I can spare time to do it (or if someone is willing to fork MySuiteA and
contribute their work).

The codecs for key-pairs are associated with the key generation functions,
for the obvious reason that key-pairs are the product of key-generation 
function.

What's not obvious is the associating of ciphergram codecs. 

There are 4 ways a ciphergram codec function can be associated with a
crypto object instance - 1) with the private-key function, 2) with the 
public-key function, 3) with the producer function, and 4) with the consumer
function. 

After some consideration, the ciphergram encoder and decoder pair is associated
with the public and private key operation functions of the PKC algorithm, as
most elements in a public-key cryptosystem, such as keys, cipher operations,
etc. all come in pairs.

Finally, the rules for determining whether a set of codec functions are 
usable with an algorithm. The rules are based on the rules of association 
descirbed above.

- A set of key-pair codec functions is usable with a PKC algorithm iff
  the query object that returns them returns the same key generation function
  as the query object that represents the PKC algorithm.

- The ciphergram encoding and decoding functions is usable with a PKC algorithm
  iff the query object that returns them returns the same public **and**
  private key operation functions as the query object that represents the PKC
  algorithm. For signature schemes, this means `PKSignFunc` and `PKVerifyFunc`
  must match; for KEMs this means `PKEncFunc` and `PKDecFunc` must match.

// (Key-pair Codec)
//     |
//     |
// _assoc thru KeyGen function with_
//     |
//     |
// (PKC Algo)
//     |
//     |
// _assoc thru Pub/Priv operating functions with_
//     |
//     |
// (Ciphergram Codec)
