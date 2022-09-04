Cross-Architecture Testing
==========================

The master testing control script performs cross-architecture testing
when run on the Debian or Ubuntu Linux distribution with certain packages
installed. Such testing ensures the correctness of the subject code on
different architectures, and ABIs, and most importantly, endianness. 
Currently, 4 architectures are tested: 

- x86-64
- ARMv8 AArch64
- PowerPC64
- SPARC64

of which, x86 and ARM are little-endian, and PowerPC and SPARC are big-endian,
all 4 of which are 64-bit.

1. How to Setup for Cross-Architecture Testing on Debian and Ubuntu
===================================================================

Prerequisites
-------------

- A Debian or an Ubuntu Linux distribution. 
- Clang/LLVM compiler.
- Linkers and Libraries.

Step 1: System Setting
----------------------

If your distribution is running on x86 (either amd64 or ia-32), 
then not much is needed to be done in this step.

However, if you're running on other architectures - e.g. an ARM port on
Raspberry Pi or Apple Silicon on QEMU or Docker - then you'll need to
setup [Multiarch](https://wiki.debian.org/Multiarch/HOWTO) in order to
install standard libraries and linkers. The essence of such setup is 
explained in the linked wiki page, and will not be repeated here.

Step 2: Clang/LLVM Compiler
---------------------------

This step is pretty simple. Just invoke the package management command and
install the `clang` compiler will do.

Step 3: Linkers and Libraries
-----------------------------

Finally, we need the linker used for producing the test executable program,
and the standard libraries to link the program with.

If you're on an x86 computer, then these all can be installed from the
`gcc-{x86-64,aarch64,powerpc64,sparc64}-linux-gnu` package. However, there's
some quirk on other architectures.

The `gcc-*` master packages we just mentioned installs some real dependencies,
including the `binutils-*` cross linkers, and `libgcc-*` standard libraries.
The full package names for `binutils-*` is:

> `binutils-{x86-64,aarch64,powerpc64,sparc64}-linux-gnu`

The full package name for `libgcc-*` is:

> `libgcc-<ver>-{x86-64,aarch64,powerpc64,sparc64}-cross`

Where `<ver>` is the version of GCC available to you. Any version should do,
and normally, the latest one is to be chosen.

By the way, there's the LLVM LLD linker, which can work for the little-endian
x86 and ARM architectures (but not the big-endian PowerPC and SPARC 
architectures).
