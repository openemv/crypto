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
