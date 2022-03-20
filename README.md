Common crypto abstraction
=========================

This library is a common crypto abstraction that can be shared by software
projects related card payment processing. The intention is to ease the porting
to different software cryptographic implementations (like MbedTLS or OpenSSL)
or porting to hardware cryptographic implementations (as found on secure
microcontrollers). The intention is also to expose simple abstractions that
are relevant to card payment processing, instead of providing for all
imaginable use cases.

Note this is not intended to be a standalone project. It is intended to be an
object library that can be added to other projects as a submodule.

Dependencies
------------

* C11 compiler such as GCC or Clang
* CMake

License
=======

Copyright (c) 2022 Leon Lynch.

This project is licensed under the terms of the MIT license. See LICENSE file.
