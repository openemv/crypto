/**
 * @file crypto_aes.c
 * @brief AES crypto helper functions using MbedTLS
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

#include <mbedtls/aes.h>

int crypto_aes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_aes_context ctx;
	uint8_t iv_buf[AES_BLOCK_SIZE];

	// Ensure that plaintext length is a multiple of the AES block length
	if ((plen & (AES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != AES_BLOCK_SIZE) {
		return -2;
	}

	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return -3;
	}

	mbedtls_aes_init(&ctx);
	r = mbedtls_aes_setkey_enc(&ctx, key, key_len * 8);
	if (r) {
		r = -4;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, AES_BLOCK_SIZE);
		r = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plen, iv_buf, plaintext, ciphertext);
	} else { // No IV implies ECB block mode
		r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
	}
	if (r) {
		r = -5;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);

	return r;
}

int crypto_aes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	int r;
	mbedtls_aes_context ctx;
	uint8_t iv_buf[AES_BLOCK_SIZE];

	// Ensure that ciphertext length is a multiple of the AES block length
	if ((clen & (AES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && clen != AES_BLOCK_SIZE) {
		return -2;
	}

	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return -3;
	}

	mbedtls_aes_init(&ctx);
	r = mbedtls_aes_setkey_dec(&ctx, key, key_len * 8);
	if (r) {
		r = -4;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, AES_BLOCK_SIZE);
		r = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, clen, iv_buf, ciphertext, plaintext);
	} else { // No IV implies ECB block mode
		r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, ciphertext, plaintext);
	}
	if (r) {
		r = -5;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);

	return r;
}

int crypto_aes_encrypt_ctr(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_aes_context ctx;

	// CTR mode state
	size_t nc_off = 0;
	unsigned char nonce_counter[AES_BLOCK_SIZE];
	unsigned char stream_block[AES_BLOCK_SIZE];

	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return -1;
	}

	// IV/nonce is required for CTR mode
	if (!iv) {
		return -2;
	}

	mbedtls_aes_init(&ctx);
	r = mbedtls_aes_setkey_enc(&ctx, key, key_len * 8);
	if (r) {
		r = -3;
		goto exit;
	}

	memcpy(nonce_counter, iv, sizeof(nonce_counter));
	memset(stream_block, 0, sizeof(stream_block));
	r = mbedtls_aes_crypt_ctr(&ctx, plen, &nc_off, nonce_counter, stream_block, plaintext, ciphertext);
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);
	crypto_cleanse(nonce_counter, sizeof(nonce_counter));
	crypto_cleanse(stream_block, sizeof(stream_block));

	return r;
}
