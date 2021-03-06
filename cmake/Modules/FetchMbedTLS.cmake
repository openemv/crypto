##############################################################################
# Copyright (c) 2021 Leon Lynch
#
# This file is licensed under the terms of the MIT license.
# See LICENSE file.
##############################################################################

# This module will define:
#
# MbedTLS_FOUND
# MbedTLS_VERSION

# This module also provides the following alias targets:
# - MbedTLS::mbedcrypto (Crypto library)
# - MbedTLS::mbedtls (TLS library)
# - MbedTLS::mbedx509 (X509 library)

include(FetchContent)

message(CHECK_START "Downloading and configuring MbedTLS...")
FetchContent_Declare(
	MbedTLS
	URL "https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.0.0.tar.gz"
	URL_HASH SHA256=525bfde06e024c1218047dee1c8b4c89312df1a4b5658711009086cda5dfaa55
)

# Use helper function to manually populate content instead of using
# FetchContent_MakeAvailable(). This allows EXCLUDE_FROM_ALL to be specified
# for add_subdirectory() and creates a separate scope for variables used by
# MbedTLS. These variables instruct MbedTLS to ignore minor compile warnings,
# disable MbedTLS programs and disable testing. The result is a faster build
# of the MbedTLS libraries.
function(add_mbedtls)
	FetchContent_GetProperties(MbedTLS)
	if(NOT MbedTLS_POPULATED)
		FetchContent_Populate(MbedTLS)

		# Enforce policy CMP0077 in subdirectory scope
		# This allows overriding options with variables
		set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)

		# Override MbedTLS build options
		set(MBEDTLS_FATAL_WARNINGS OFF)
		set(ENABLE_PROGRAMS OFF)
		set(ENABLE_TESTING OFF)
		add_subdirectory(${mbedtls_SOURCE_DIR} ${mbedtls_BINARY_DIR} EXCLUDE_FROM_ALL)
	endif()
endfunction()

add_mbedtls()
message(CHECK_PASS "done")

# Add library aliases according to the names in _deps/mbedtls-src/library/CMakeLists.txt
add_library(MbedTLS::mbedcrypto ALIAS mbedcrypto)
add_library(MbedTLS::mbedtls ALIAS mbedtls)
add_library(MbedTLS::mbedx509 ALIAS mbedx509)

# MbedTLS is now ready to use
set(MbedTLS_FOUND True)
set(MbedTLS_VERSION 3.0.0)
