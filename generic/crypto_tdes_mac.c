/**
 * @file crypto_tdes_mac.c
 * @brief TDES Message Authentication Code (MAC) crypto helper functions
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

int crypto_tdes2_retail_mac(const void* key, const void* buf, size_t buf_len, void* mac)
{
	int r;
	size_t initial_len;
	size_t remaining_len;
	uint8_t iv[DES_BLOCK_SIZE];
	uint8_t last_block[DES_BLOCK_SIZE];
	uint8_t result[DES_BLOCK_SIZE];

	if (!key || !mac) {
		return 1;
	}
	if (buf_len && !buf) {
		return 2;
	}

	// See ISO 9797-1, MAC algorithm 3, Padding method 1
	// - No key derivation
	// - Final iteration 1
	// - Output transformation 3
	// - Zero padding

	// Determine initial length and remaining length based on last block boundary
	remaining_len = buf_len & (DES_BLOCK_SIZE-1);
	if (buf_len && !remaining_len) {
		remaining_len = DES_BLOCK_SIZE; // For last block
	}
	initial_len = buf_len - remaining_len;

	// Compute DES CBC-MAC for all but the last block
	memset(iv, 0, sizeof(iv)); // Start with zero IV
	for (size_t i = 0; i < initial_len; i += DES_BLOCK_SIZE) {
		r = crypto_des_encrypt(key, iv, buf + i, DES_BLOCK_SIZE, iv);
		if (r) {
			goto exit;
		}
	}

	// Padding method 1:
	// Zero padding of last block, even if there was no input data
	memset(last_block, 0, sizeof(last_block));
	if (remaining_len) {
		memcpy(last_block, buf + buf_len - remaining_len, remaining_len);
	}

	// Output transformation 3:
	// TDES CBC-MAC of last block
	r = crypto_tdes2_encrypt(key, iv, last_block, sizeof(last_block), result);
	if (r) {
		goto exit;
	}

	// Truncate result
	memcpy(mac, result, DES_RETAIL_MAC_SIZE);

	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(iv, sizeof(iv));
	crypto_cleanse(last_block, sizeof(last_block));
	crypto_cleanse(result, sizeof(result));

	return r;
}

int crypto_tdes_cbcmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* mac
)
{
	int r;
	uint8_t iv[DES_BLOCK_SIZE];

	if (!key || !buf || !buf_len || !mac) {
		return 1;
	}
	if (key_len != TDES2_KEY_SIZE && key_len != TDES3_KEY_SIZE) {
		// Invalid key length
		return 2;
	}

	// See ISO 9797-1:2011 MAC algorithm 1
	// - No key derivation
	// - Final iteration 1
	// - Output transformation 1
	// - May be used with padding method 1, 2 or 3

	// This implementation does not apply padding and the caller should ensure
	// that the input buffer length is a multiple of DES_BLOCK_SIZE
	if ((buf_len & (DES_BLOCK_SIZE-1)) != 0) {
		return 3;
	}

	// Compute TDES CBC-MAC
	memset(iv, 0, sizeof(iv)); // Start with zero IV
	for (size_t i = 0; i < buf_len; i += DES_BLOCK_SIZE) {
		r = crypto_tdes_encrypt(key, key_len, iv, buf + i, DES_BLOCK_SIZE, iv);
		if (r) {
			goto exit;
		}
	}

	// Copy MAC result without truncation
	memcpy(mac, iv, DES_CBCMAC_SIZE);

	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(iv, sizeof(iv));

	return r;
}
