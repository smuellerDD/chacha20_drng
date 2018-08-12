ChaCha20 DRNG
=============

The ChaCha20 DRNG is a complete standalone implementation of a
deterministic random number generator. It does not need any external
cryptographic support.

The ChaCha20 DRNG is implemented using ideas specified in SP800-90A,
AIS 20/31 as well as specified by Peter Gutmann's 1998 Usenix Security
Symposium paper: "Software Generation of Practically Strong Random Numbers".
The following list enumerates the different properties offered with the
ChaCha20 DRNG.

Origin
------

The ChaCha20 DRNG user space implementation was developed to allow an in-depth
study of the DRNG for its use as part of the
[Linux Random Number Generator](https://github.com/smuellerDD/lrng).

Both implementations with respect to the pseudo random number generator are
identical. Naturally, the ChaCha20 DRNG user space includes the ChaCha20
block operation, self tests and the pulling of data from seed sources.

Seed Sources
============

The ChaCha20 DRNG code base allows the following seed sources to be used.
These seed sources are enabled or disabled in the Makefile. If more than one
seed source is enabled, the seed of all seed sources is concatenated.

* Jitter RNG: If the file jitterentropy-base.c exists in the current directory,
  the Jitter RNG is used as noise source.

* getrandom system call

* /dev/random device file

Directory Structure
===================

base directory -- directory holding the library

test/ -- functional verification code

The code in each directory is intended to be compiled independently.

Version Numbers
===============
The version numbers for this library have the following schema:
MAJOR.MINOR.PATCHLEVEL

Changes in the major number implies API and ABI incompatible changes, or
functional changes that require consumer to be updated (as long as this 
number is zero, the API is not considered stable and can change without a 
bump of the major version).

Changes in the minor version are API compatible, but the ABI may change. 
Functional enhancements only are added. Thus, a consumer can be left 
unchanged if enhancements are not considered. The consumer only needs to 
be recompiled.

Patchlevel changes are API / ABI compatible. No functional changes, no
enhancements are made. This release is a bug fixe release only. The
consumer can be left unchanged and does not need to be recompiled.


Make Targets
============

The following make targets are applicable:

* make              # compile library

* make install      # install library into $PREFIX

* make scan         # use CLANG static code analyzer

* make man          # compile man pages in doc/man

* make maninstall   # install man pages into $PREFIX

* make pdf          # generate documentation in PDF

* make ps           # generate documentation in PS

* make html         # generate documentation as HTML in doc/html


Compilation
===========

The Makefile compiles ChaCha20 DRNG as a shared library.

The "install" Makefile target installs libkcapi under /usr/local/lib or
/usr/local/lib64. The header file is installed to /usr/local/include.


Test cases
==========

The test/ directory contains test cases to verify the correct operation of
this library.

Author
======
Stephan Mueller <smueller@chronox.de>
