Common crypto abstraction
=========================

This project is a common crypto abstraction that can be shared by software
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

Usage
-----

This CMake project can be added to CMake parent projects using the CMake
`add_subdirectory()` command. When this project is added to a parent project,
the `test` subdirectory is not added automatically. Parent projects can add
the `test` subdirectory manually if the tests are of interest to the parent
project. However, note that the `test` subdirectory requires the CMake `CTest`
module and that the tests will only be built when the `BUILD_TESTING` option
is enabled (`CTest` enables it by default).

An example of adding this project to a parent project would be:
```
add_subdirectory(crypto)
add_subdirectory(crypto/test)
```

Note that it is not necessary, and not recommended, for `EXCLUDE_FROM_ALL` to
be specified when adding this project to a parent project. This project
already specifies `EXCLUDE_FROM_ALL` for each `add_library()`.

MbedTLS options
---------------

If MbedTLS is not available, the `FETCH_MBEDTLS` option can be specified to
download and build a local copy during the CMake build. If the platform
provides MbedTLS but it is desirable to build a local copy instead, the
`CMAKE_DISABLE_FIND_PACKAGE_MbedTLS` can be used to prevent CMake from finding
it. This option can even be used without `FETCH_MBEDTLS` to ensure that CMake
finds and uses a cryptographic implementation other than MbedTLS.

When specifying `FETCH_MBEDTLS` together with `BUILD_SHARED_LIBS`, it may also
be necessary to use `USE_SHARED_MBEDTLS_LIBRARY` to ensure that MbedTLS is
built as a shared library.

When specifying `FETCH_MBEDTLS`, the local copy of MbedTLS will add CTest
tests. It is therefore important not to specify `EXCLUDE_FROM_ALL` when adding
this project to a parent project as that will add the tests but exclude them
from the build, causing testing to fail.

License
-------

Copyright (c) 2021, 2022 Leon Lynch.

This project is licensed under the terms of the MIT license. See LICENSE file.
