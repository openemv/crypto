/**
 * @file crypto_aes_kcv.c
 * @brief AES Key Check Value (KCV) crypto helper functions
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

#include "crypto_aes.h"
#include "crypto_mem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int crypto_aes_kcv(const void* key, size_t key_len, void* kcv)
{
	int r;
	uint8_t zero[AES_BLOCK_SIZE];
	uint8_t ciphertext[AES_BLOCK_SIZE];

	if (!key || !kcv) {
		return 1;
	}
	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return 2;
	}

	// See ANSI X9.24-1:2017, A.3 CMAC-based Check values

	// Zero KCV in case of error
	memset(kcv, 0, AES_KCV_SIZE);

	// Use input block populated with 0x00
	memset(zero, 0x00, sizeof(zero));

	// Compute CMAC of input block using input key
	r = crypto_aes_cmac(key, key_len, zero, sizeof(zero), ciphertext);
	if (r) {
		return r;
	}

	// KCV is always first 5 bytes of ciphertext
	memcpy(kcv, ciphertext, AES_KCV_SIZE);

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(ciphertext, sizeof(ciphertext));

	return r;
}
