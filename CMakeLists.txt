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
	VERSION 0.0.1
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
