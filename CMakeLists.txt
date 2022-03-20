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

find_package(MbedTLS 2.16) # Latest version available on Ubuntu 20.04 and Fedora 34
