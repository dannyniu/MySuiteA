Cross-Architecture Testing
==========================

The master testing control script performs cross-architecture testing
when run on the Debian or Ubuntu Linux distribution with certain packages
installed. Such testing ensures the correctness of the subject code on
different architectures, and ABIs, and most importantly, endianness. 
Currently, 3 architecture families are tested: 

- x86, 32-bit: i686, 64-bit: x86_64
- ARM, 64-bit: AArch64
- PowerPC, 32-bit, and 64-bit

of which, x86 and ARM are little-endian, and PowerPC is big-endian.

Previously, there was the SPARC64 target. Testing on recent version of Debian
show this architecture being broken and no longer a suitable test target.

Additionally, 64-bit RISC-V is added as an explorational optimization target.
Its installation is recommended.

I. How to Setup for Cross-Architecture Testing on Debian and Ubuntu
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
`gcc-${archs}-linux-gnu` packages, where `${archs}` is (one or some of):

> `{i686,x86_64,aarch64,riscv64,powerpc,powerpc64}`

However, there's some quirk on other architectures.

The `gcc-*` master packages we just mentioned installs some real dependencies,
including the `binutils-*` cross linkers, and `libgcc-*` standard libraries.
The full package names for `binutils-*` is:

> `binutils-${archs}-linux-gnu`

The full package name for `libgcc-*` is:

> `libgcc-<ver>-${archs_abbrev}-cross`

Where `<ver>` is the version of GCC available to you. Any version should do,
and normally, the latest one is to be chosen. And `${archs_abbrev} is 
(one or some of):

> {i386,amd64,arm64,riscv64,powerpc,ppc64}

By the way, there's the LLVM LLD linker, which can work for the little-endian
x86 and ARM, and 32-bit PowerPC architectures (but not the big-endian PowerPC64
and SPARC64 architectures).
