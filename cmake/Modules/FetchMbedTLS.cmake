##############################################################################
# Copyright 2021-2022, 2024-2025 Leon Lynch
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

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.24")
	# CMake >=3.24 has changed the behaviour of FetchContent_Declare() but the
	# new behaviour doesn't impact this project. The old behaviour can still be
	# accessed using the DOWNLOAD_EXTRACT_TIMESTAMP parameter which causes
	# older CMake versions to fail. So it's easier to simply accept the new
	# behaviour if it's available to suppress the warning.
	cmake_policy(SET CMP0135 NEW)
endif()

message(CHECK_START "Downloading and configuring MbedTLS...")

# Use helper function to manually populate content instead of using
# FetchContent_MakeAvailable(). This allows EXCLUDE_FROM_ALL to be specified
# for add_subdirectory() and creates a separate scope for variables used by
# MbedTLS. These variables instruct MbedTLS to ignore minor compile warnings,
# disable MbedTLS programs and disable testing. The result is a faster build
# of the MbedTLS libraries.
# It is also useful to build MbedTLS as standalone although it is being added
# as a subdirectory. This is because newer version of MbedTLS will set
# MBEDTLS_AS_SUBPROJECT, which in turn sets DISABLE_PACKAGE_CONFIG_AND_INSTALL,
# which in turn disables the target exports which may be needed by parent
# projects.
function(add_mbedtls)
	FetchContent_GetProperties(MbedTLS)
	if(NOT MbedTLS_POPULATED)
		FetchContent_Populate(
			MbedTLS
			# Policy CMP0169 requires these parameters to be here instead of
			# FetchContent_Declare() to avoid a deprecated form of
			# FetchContent_Populate()
			URL "https://github.com/Mbed-TLS/mbedtls/releases/download/v3.6.3.1/mbedtls-3.6.3.1.tar.bz2"
			URL_HASH SHA256=243ed496d5f88a5b3791021be2800aac821b9a4cc16e7134aa413c58b4c20e0c
			PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/mbedtls_cmake_version_fix.patch
		)

		# Enforce policy CMP0077 in subdirectory scope
		# This allows overriding options with variables
		set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)

		# Override MbedTLS build options
		set(MBEDTLS_FATAL_WARNINGS OFF)
		set(ENABLE_PROGRAMS OFF)
		set(ENABLE_TESTING OFF)
		set(MBEDTLS_AS_SUBPROJECT OFF)
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
set(MbedTLS_VERSION 3.6.3.1)
