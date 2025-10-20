/**
 * @file crypto_aes_mac.c
 * @brief AES Message Authentication Code (MAC) crypto helper functions
 *
 * Copyright 2021-2022 Leon Lynch
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

// See NIST SP 800-38B, section 5.3
static const uint8_t crypto_aes_cmac_subkey_r128[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

static int crypto_aes_cmac_derive_subkeys(const void* key, size_t key_len, void* k1, void* k2)
{
	int r;
	uint8_t zero[AES_BLOCK_SIZE];
	uint8_t l_buf[AES_BLOCK_SIZE];

	// See ISO 9797-1:2011, section 6.2.3
	// See NIST SP 800-38B, section 6.1

	// Encrypt zero block with input key
	memset(zero, 0, sizeof(zero));
	r = crypto_aes_encrypt_ecb(key, key_len, zero, l_buf);
	if (r) {
		// Internal error
		goto exit;
	}

	// Generate K1 subkey
	memcpy(k1, l_buf, AES_BLOCK_SIZE);
	r = crypto_lshift(k1, AES_BLOCK_SIZE);
	// If carry bit is set, XOR with R128
	if (r) {
		crypto_xor(k1, crypto_aes_cmac_subkey_r128, sizeof(crypto_aes_cmac_subkey_r128));
	}

	// Generate K2 subkey
	memcpy(k2, k1, AES_BLOCK_SIZE);
	r = crypto_lshift(k2, AES_BLOCK_SIZE);
	// If carry bit is set, XOR with R128
	if (r) {
		crypto_xor(k2, crypto_aes_cmac_subkey_r128, sizeof(crypto_aes_cmac_subkey_r128));
	}

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(l_buf, sizeof(l_buf));

	return r;
}

int crypto_aes_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint8_t k1[AES_BLOCK_SIZE];
	uint8_t k2[AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	const void* ptr = buf;

	size_t last_block_len;
	uint8_t last_block[AES_BLOCK_SIZE];

	if (!key || !cmac) {
		return 1;
	}
	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return 2;
	}
	if (buf_len && !buf) {
		return 3;
	}

	// See ISO 9797-1:2011 MAC algorithm 5
	// - Key derivation method 2
	// - Final iteration 3
	// - Output transformation 1
	// - Padding method 4

	// See NIST SP 800-38B, section 6.2
	// If CMAC message input (M) is a multiple of the cipher block size, then
	// the last message input block is XOR'd with subkey K1.
	// If CMAC message input (M) is not a multiple of the cipher block size,
	// then the last message input block is padded and XOR'd with subkey K2.
	// The cipher is applied in CBC mode to all message input blocks,
	// including the modified last block.

	// Derive CMAC subkeys
	r = crypto_aes_cmac_derive_subkeys(key, key_len, k1, k2);
	if (r) {
		// Internal error
		goto exit;
	}

	// Compute CMAC
	// See ISO 9797-1:2011 MAC algorithm 5
	// See NIST SP 800-38B, section 6.2
	memset(iv, 0, sizeof(iv)); // Start with zero IV
	if (buf_len > AES_BLOCK_SIZE) {
		// For all blocks except the last block, compute CBC-MAC
		for (size_t i = 0; i < buf_len - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
			r = crypto_aes_encrypt(key, key_len, iv, ptr, AES_BLOCK_SIZE, iv);
			if (r) {
				// Internal error
				goto exit;
			}

			ptr += AES_BLOCK_SIZE;
		}
	}

	// Prepare last block
	if (buf_len) {
		last_block_len = buf_len - (ptr - buf);
	} else {
		last_block_len = 0;
	}
	if (last_block_len == AES_BLOCK_SIZE) {
		// Final iteration 3:
		// If message input is a multiple of cipher block size,
		// XOR with subkey K1
		crypto_xor(iv, k1, sizeof(iv));
	} else {
		// Final iteration 3:
		// If message input is not a multiple of cipher block size,
		// XOR with subkey K2
		crypto_xor(iv, k2, sizeof(iv));

		// Build new last block
		memcpy(last_block, ptr, last_block_len);

		// Padding method 4:
		// Pad last block with 1 bit followed by zeros
		last_block[last_block_len] = 0x80;
		if (last_block_len + 1 < AES_BLOCK_SIZE) {
			memset(last_block + last_block_len + 1, 0, AES_BLOCK_SIZE - last_block_len - 1);
		}

		ptr = last_block;
	}

	// Output transformation 1:
	// Process last block
	r = crypto_aes_encrypt(key, key_len, iv, ptr, AES_BLOCK_SIZE, cmac);
	if (r) {
		// Internal error
		goto exit;
	}

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	crypto_cleanse(k1, sizeof(k1));
	crypto_cleanse(k2, sizeof(k2));
	crypto_cleanse(iv, sizeof(iv));
	crypto_cleanse(last_block, sizeof(last_block));

	return r;
}
