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
