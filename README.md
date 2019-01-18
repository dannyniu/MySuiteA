# MySuiteA

Cryptographic code samples by DannyNiu/NJF. 

Algorithmic primitives are layered according to: 

0. Datum (datum, exec)
1. Primitive (rijndael, fips-180, keccak, etc.)
2. Utility (encryption, hash, xof, etc.)
~~3. Functionality (KEM, signature, etc.)~~

What happened to public-key cryptography in MySuiteA?

Well, since symmetric-key cryptography is much easier to test than
pubkey crypto, crypto library and programs are proliferous, and
a suite of symmetric-key cryptography code samples serves well,
effort on public-key cryptography in MySuiteA had been given up. 
