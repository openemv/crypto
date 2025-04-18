##############################################################################
# Copyright 2022, 2025 Leon Lynch
#
# This file is licensed under the terms of the MIT license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

if(BUILD_TESTING)
	if(crypto_IS_TOP_LEVEL OR "crypto_tdes" IN_LIST CRYPTO_TESTS)
		add_executable(crypto_tdes2_retail_mac_test crypto_tdes2_retail_mac_test.c)
		target_link_libraries(crypto_tdes2_retail_mac_test crypto_tdes crypto_mem)
		add_test(crypto_tdes2_retail_mac_test crypto_tdes2_retail_mac_test)

		add_executable(crypto_tdes_cmac_test crypto_tdes_cmac_test.c)
		target_link_libraries(crypto_tdes_cmac_test crypto_tdes crypto_mem)
		add_test(crypto_tdes_cmac_test crypto_tdes_cmac_test)
	endif()

	if(crypto_IS_TOP_LEVEL OR "crypto_aes" IN_LIST CRYPTO_TESTS)
		add_executable(crypto_aes_cmac_test crypto_aes_cmac_test.c)
		target_link_libraries(crypto_aes_cmac_test crypto_aes crypto_mem)
		add_test(crypto_aes_cmac_test crypto_aes_cmac_test)
	endif()

	if(crypto_IS_TOP_LEVEL OR "crypto_hmac" IN_LIST CRYPTO_TESTS)
		add_executable(crypto_hmac_test crypto_hmac_test.c)
		target_link_libraries(crypto_hmac_test crypto_hmac)
		add_test(crypto_hmac_test crypto_hmac_test)
	endif()

	if(crypto_IS_TOP_LEVEL OR "crypto_sha" IN_LIST CRYPTO_TESTS)
		add_executable(crypto_sha1_test crypto_sha1_test.c)
		target_link_libraries(crypto_sha1_test crypto_sha)
		add_test(crypto_sha1_test crypto_sha1_test)

		add_executable(crypto_sha256_test crypto_sha256_test.c)
		target_link_libraries(crypto_sha256_test crypto_sha)
		add_test(crypto_sha256_test crypto_sha256_test)
	endif()

	if(crypto_IS_TOP_LEVEL OR "crypto_rsa" IN_LIST CRYPTO_TESTS)
		add_executable(crypto_rsa_test crypto_rsa_test.c)
		target_link_libraries(crypto_rsa_test crypto_rsa)
		add_test(crypto_rsa_test crypto_rsa_test)
	endif()
endif()
