/**
 * @file crypto_tdes_kcv.c
 * @brief TDES Key Check Value (KCV) crypto helper functions
 *
 * Copyright (c) 2021, 2022 Leon Lynch
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "crypto_tdes.h"
#include "crypto_mem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int crypto_tdes_kcv_legacy(const void* key, size_t key_len, void* kcv)
{
	int r;
	uint8_t zero[DES_BLOCK_SIZE];
	uint8_t ciphertext[DES_BLOCK_SIZE];

	if (!key || !kcv) {
		return 1;
	}
	if (key_len != TDES2_KEY_SIZE && key_len != TDES3_KEY_SIZE) {
		return 2;
	}

	// See ANSI X9.24-1:2017, A.2 Legacy Approach

	// Zero KCV in case of error
	memset(kcv, 0, DES_KCV_SIZE_LEGACY);

	// Use input block populated with 0x00
	memset(zero, 0x00, sizeof(zero));

	// Encrypt zero block with input key
	r = crypto_tdes_encrypt_ecb(key, key_len, zero, ciphertext);
	if (r) {
		goto exit;
	}

	// KCV is always first 3 bytes of ciphertext
	memcpy(kcv, ciphertext, DES_KCV_SIZE_LEGACY);

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(ciphertext, sizeof(ciphertext));

	return r;
}

int crypto_tdes_kcv_cmac(const void* key, size_t key_len, void* kcv)
{
	int r;
	uint8_t zero[DES_BLOCK_SIZE];
	uint8_t ciphertext[DES_BLOCK_SIZE];

	if (!key || !kcv) {
		return 1;
	}
	if (key_len != TDES2_KEY_SIZE && key_len != TDES3_KEY_SIZE) {
		return 2;
	}

	// See ANSI X9.24-1:2017, A.3 CMAC-based Check values

	// Zero KCV in case of error
	memset(kcv, 0, DES_KCV_SIZE_CMAC);

	// Use input block populated with 0x00
	memset(zero, 0x00, sizeof(zero));

	// Compute CMAC of input block using input key
	r = crypto_tdes_cmac(key, key_len, zero, sizeof(zero), ciphertext);
	if (r) {
		goto exit;
	}

	// KCV is always first 5 bytes of ciphertext
	memcpy(kcv, ciphertext, DES_KCV_SIZE_CMAC);

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(ciphertext, sizeof(ciphertext));

	return r;
}
