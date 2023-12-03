/**
 * @file crypto_tdes.c
 * @brief DES and TDES crypto helper functions using MbedTLS
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

#include "crypto_tdes.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/des.h>

int crypto_des_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_des_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des_init(&ctx);
	r = mbedtls_des_setkey_enc(&ctx, key);
	if (r) {
		r = -3;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, plen, iv_buf, plaintext, ciphertext);
	} else { // No IV implies ECB block mode
		r = mbedtls_des_crypt_ecb(&ctx, plaintext, ciphertext);
	}
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des_free(&ctx);

	return r;
}

int crypto_tdes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_des3_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des3_init(&ctx);

	switch (key_len) {
		case TDES2_KEY_SIZE: // Double length TDES key
			r = mbedtls_des3_set2key_enc(&ctx, key);
			break;

		case TDES3_KEY_SIZE: // Triple length TDES key
			r = mbedtls_des3_set3key_enc(&ctx, key);
			break;

		default:
			r = -3;
			goto exit;
	}
	if (r) {
		r = -4;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, plen, iv_buf, plaintext, ciphertext);
	} else { // No IV implies ECB block mode
		r = mbedtls_des3_crypt_ecb(&ctx, plaintext, ciphertext);
	}
	if (r) {
		r = -5;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

	return r;
}

int crypto_tdes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	int r;
	mbedtls_des3_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that ciphertext length is a multiple of the DES block length
	if ((clen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && clen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des3_init(&ctx);

	switch (key_len) {
		case TDES2_KEY_SIZE: // Double length TDES key
			r = mbedtls_des3_set2key_dec(&ctx, key);
			break;

		case TDES3_KEY_SIZE: // Triple length TDES key
			r = mbedtls_des3_set3key_dec(&ctx, key);
			break;

		default:
			r = -3;
			goto exit;
	}
	if (r) {
		r = -4;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, clen, iv_buf, ciphertext, plaintext);
	} else { // No IV implies ECB block mode
		r = mbedtls_des3_crypt_ecb(&ctx, ciphertext, plaintext);
	}
	if (r) {
		r = -5;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

	return r;
}
