Common crypto abstraction
=========================

This library is a common crypto abstraction that can be shared by software
projects related to card payment processing. The intention is to ease porting
to different software cryptographic implementations (like MbedTLS or OpenSSL)
or porting to hardware cryptographic implementations (as found on secure
microcontrollers). The intention is also to expose simple abstractions that
are relevant to card payment processing, instead of providing for all
imaginable use cases.

Note that this is not intended to be a standalone project. It is intended to
be a collection of object libraries that can be added to other projects as a
submodule. The object libraries have hidden symbol visibility such that they
are not exposed as part of the API of other projects.

Dependencies
------------

* C11 compiler such as GCC or Clang
* CMake
* At least one supported cryptographic implementation (see below)

Supported cryptographic implementations:
* MbedTLS
* OpenSSL

License
-------

Copyright (c) 2021, 2022 Leon Lynch.

This project is licensed under the terms of the MIT license. See LICENSE file.
