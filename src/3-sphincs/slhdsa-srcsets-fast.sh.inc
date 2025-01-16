# DannyNiu/NJF, 2024-10-09. Public Domain.

cflags="-D HashN=16 -D HashH=63 -D LongHash=SHA256 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-128s ($srcset_common)"
#tests_run

cflags="-D HashN=16 -D HashH=66 -D LongHash=SHA256 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-128f ($srcset_common)"
tests_run

cflags="-D HashN=24 -D HashH=63 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-192s ($srcset_common)"
#tests_run

cflags="-D HashN=24 -D HashH=66 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-192f ($srcset_common)"
tests_run

cflags="-D HashN=32 -D HashH=64 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-256s ($srcset_common)"
#tests_run

cflags="-D HashN=32 -D HashH=68 -D LongHash=SHA512 -D ShortHash=SHA256"
srcset="SLH-DSA-SHA2-256f ($srcset_common)"
tests_run

cflags="-D HashN=16 -D HashH=63 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-128s ($srcset_common)"
#tests_run

cflags="-D HashN=16 -D HashH=66 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-128f ($srcset_common)"
tests_run

cflags="-D HashN=24 -D HashH=63 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-192s ($srcset_common)"
#tests_run

cflags="-D HashN=24 -D HashH=66 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-192f ($srcset_common)"
tests_run

cflags="-D HashN=32 -D HashH=64 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-256s ($srcset_common)"
#tests_run

cflags="-D HashN=32 -D HashH=68 -D LongHash=SHAKE256 -D ShortHash=SHAKE256"
srcset="SLH-DSA-SHAKE-256f ($srcset_common)"
tests_run
