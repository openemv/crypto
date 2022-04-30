##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the MIT license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

# NOTE: This is not intended to be a standalone project. It is intended to be
# an object library that can be added to other projects.

project(crypto
	VERSION 0.1.2
	DESCRIPTION "OpenEMV common crypto abstraction"
	HOMEPAGE_URL "https://github.com/openemv/crypto"
	LANGUAGES C
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

# Prefer MbedTLS and allow the FETCH_MBEDTLS option to download and build
# a local copy of MbedTLS for monolithic builds on platforms without package
# managers like Windows and MacOS.
find_package(MbedTLS 2.16) # Latest version available on Ubuntu 20.04 and Fedora 34
option(FETCH_MBEDTLS "Download and build MbedTLS")
if(NOT MbedTLS_FOUND AND FETCH_MBEDTLS)
	include(FetchMbedTLS)
endif()

if(NOT MbedTLS_FOUND)
	# Alternatively, try OpenSSL
	find_package(OpenSSL 1.1 COMPONENTS Crypto)
endif()

# Choose crypto implementation and inform parent scope.
# The CRYPTO_PACKAGE_DEPENDENCIES variable is set for the parent scope to
# facilitate the generation of CMake package configuration files.
# The CRYPTO_PKGCONFIG_REQ_PRIV and CRYPTO_PKGCONFIG_LIBS_PRIV variables are
# set for the parent scope to facilitate the generation of pkgconfig files.
if(MbedTLS_FOUND)
	# Prefer MbedTLS
	message(STATUS "Using MbedTLS")
	set(USE_MBEDTLS TRUE)
	list(APPEND CRYPTO_PACKAGE_DEPENDENCIES "MbedTLS 2.16")
	set(CRYPTO_PACKAGE_DEPENDENCIES ${CRYPTO_PACKAGE_DEPENDENCIES} PARENT_SCOPE)
	# NOTE: MbedTLS has no pkgconfig file so CRYPTO_PKGCONFIG_REQ_PRIV cannot be set
	set(CRYPTO_PKGCONFIG_LIBS_PRIV "-lmbedcrypto" PARENT_SCOPE)
elseif(OpenSSL_FOUND)
	message(STATUS "Using OpenSSL")
	set(USE_OPENSSL TRUE)
	list(APPEND CRYPTO_PACKAGE_DEPENDENCIES "OpenSSL 1.1 COMPONENTS Crypto")
	set(CRYPTO_PACKAGE_DEPENDENCIES ${CRYPTO_PACKAGE_DEPENDENCIES} PARENT_SCOPE)
	set(CRYPTO_PKGCONFIG_REQ_PRIV "libcrypto" PARENT_SCOPE)
	set(CRYPTO_PKGCONFIG_LIBS_PRIV "-lcrypto" PARENT_SCOPE)
else()
	message(FATAL_ERROR "Either MbedTLS or OpenSSL is required")
endif()

# Memory helper library
add_library(crypto_mem OBJECT EXCLUDE_FROM_ALL)
target_sources(crypto_mem PRIVATE generic/crypto_mem.c)
target_include_directories(crypto_mem PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# Random data helper library
add_library(crypto_rand OBJECT EXCLUDE_FROM_ALL)
target_include_directories(crypto_rand PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# TDES crypto library
add_library(crypto_tdes OBJECT EXCLUDE_FROM_ALL)
target_include_directories(crypto_tdes PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# AES crypto library
add_library(crypto_aes OBJECT EXCLUDE_FROM_ALL)
target_include_directories(crypto_aes PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# HMAC crypto library
add_library(crypto_hmac OBJECT EXCLUDE_FROM_ALL)
target_include_directories(crypto_hmac PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(USE_MBEDTLS)
	# Random data helper library
	target_sources(crypto_rand PRIVATE mbedtls/crypto_rand.c)
	target_link_libraries(crypto_rand PRIVATE MbedTLS::mbedcrypto)

	# TDES crypto library
	target_sources(crypto_tdes PRIVATE mbedtls/crypto_tdes.c generic/crypto_tdes_mac.c generic/crypto_tdes_kcv.c)
	target_link_libraries(crypto_tdes PRIVATE MbedTLS::mbedcrypto)

	# AES crypto library
	target_sources(crypto_aes PRIVATE mbedtls/crypto_aes.c generic/crypto_aes_mac.c generic/crypto_aes_kcv.c)
	target_link_libraries(crypto_aes PRIVATE MbedTLS::mbedcrypto)

	# HMAC crypto library
	target_sources(crypto_hmac PRIVATE mbedtls/crypto_hmac.c)
	target_link_libraries(crypto_hmac PRIVATE MbedTLS::mbedcrypto)
elseif(USE_OPENSSL)
	# Random data helper library
	target_sources(crypto_rand PRIVATE openssl/crypto_rand.c)
	target_link_libraries(crypto_rand PRIVATE OpenSSL::Crypto)

	# TDES crypto library
	target_sources(crypto_tdes PRIVATE openssl/crypto_tdes.c generic/crypto_tdes_mac.c generic/crypto_tdes_kcv.c)
	target_link_libraries(crypto_tdes PRIVATE OpenSSL::Crypto)

	# AES crypto library
	target_sources(crypto_aes PRIVATE openssl/crypto_aes.c generic/crypto_aes_mac.c generic/crypto_aes_kcv.c)
	target_link_libraries(crypto_aes PRIVATE OpenSSL::Crypto)

	# HMAC crypto library
	target_sources(crypto_hmac PRIVATE openssl/crypto_hmac.c)
	target_link_libraries(crypto_hmac PRIVATE OpenSSL::Crypto)
endif()

# Configure various compilation properties
set_target_properties(
	crypto_mem
	crypto_rand
	crypto_tdes
	crypto_aes
	crypto_hmac
	PROPERTIES
		C_STANDARD 11
		C_EXTENSIONS OFF
		C_VISIBILITY_PRESET hidden
)
if(BUILD_SHARED_LIBS)
	set_target_properties(
		crypto_mem
		crypto_rand
		crypto_tdes
		crypto_aes
		crypto_hmac
		PROPERTIES
			POSITION_INDEPENDENT_CODE True
	)
endif()

# Only add tests if this is the top-level project
if(crypto_IS_TOP_LEVEL)
	include(CTest)
	add_subdirectory(test)
endif()
