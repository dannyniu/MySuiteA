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

The proposed change is currently underway as of 2021-09-03.

---


2021-09-03b
===========

It's decided that information macros for blockciphers, hash functions, and
permutations shall not nest lower-level primitives. This restriction is added
to:

1. ease the implementation of some higher level primitives (e.g. CTR-DRBG
   relies on block ciphers, and is built without provision for nested
   template instantiation; the same can be said for HMAC);

2. limit the nesting levels of information macros (e.g. PKCS#1 paddings of
   MySuiteA RSA implementations require 2 hash functions - 1 for message,
   1 for MGF. They would be able to share working context memory space if
   it's possible to calculate the maximum of 2 sizes, even though in most
   cases, they should be the same hash function. For more on this, see
   https://stackoverflow.com/q/68992622 ).