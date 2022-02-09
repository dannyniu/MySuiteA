MySuiteA
========================================================

**Cryptographic Code Library from DannyNiu/NJF**

MySuiteA is a suite of C language source code library for cryptographic
algorithms. It's written with modularity, self-sufficiency, API uniforminity
in mind, and is highly portable. 

Features
--------

- **API Uniforminity.**

Uniform APIs are designed for each type of primitives, allowing their instances
to be created at compile, link, and run time. Higher-level algorithms may take
lower-level primitives as parameters when instantiating (e.g. GCM mode plus AES
blockcipher, RSA algorithm with SHA-256 hash function).

- **Layered Implementation.**

All objects, functions, and data types are layered according to:

0. Datum (datum, exec)
1. Primitive (rijndael, fips-180, keccak, etc.)
2. Utility (encryption, hash, xof, etc.)
3. Functionality (KEM, signature, etc.)

Each type of concern are encapsulated within a specific layer, allowing
modular code reuse at higher layer, supporting modular instantiability.

- **Only Algorithms.**

All codes constituting the algorithms are written absent any function call
to hosted libraries (i.e. no `malloc` or `fwrite`, etc.). Any necessary
working contexts are allocated by the user/caller before performing any
cryptographic computation.

MySuiteA will not, and cannot correctly adapt to all usage scenario, therefore
any platform dependent concerns such as thread, async-signal, and async-cancel
safety are left out of the suite and are to be handled by the user/caller.

- **International.**

Apart from US algorithms, a select few important national/regional from
elsewhere around the globe are included in the suite. At the same time, 
an inclusion criteria is established to prevent scope creep.
