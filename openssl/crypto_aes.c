/**
 * @file crypto_aes.c
 * @brief AES crypto helper functions using OpenSSL
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

int crypto_aes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	int clen;
	int clen2;

	// Ensure that plaintext length is a multiple of the AES block length
	if ((plen & (AES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != AES_BLOCK_SIZE) {
		return -2;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -3;
		goto exit;
	}

	switch (key_len) {
		case AES128_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
			}
			break;

		case AES192_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
			}
			break;

		case AES256_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
			}
			break;

		default:
			r = -4;
			goto exit;
	}
	if (!r) {
		r = -5;
		goto exit;
	}

	// Disable padding
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	clen = 0;
	r = EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
	if (!r) {
		r = -6;
		goto exit;
	}

	clen2 = 0;
	r = EVP_EncryptFinal_ex(ctx, ciphertext + clen, &clen2);
	if (!r) {
		r = -7;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	EVP_CIPHER_CTX_free(ctx);

	return r;
}

int crypto_aes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	int plen;
	int plen2;

	// Ensure that ciphertext length is a multiple of the AES block length
	if ((clen & (AES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && clen != AES_BLOCK_SIZE) {
		return -2;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -3;
		goto exit;
	}

	switch (key_len) {
		case AES128_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
			}
			break;

		case AES192_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
			}
			break;

		case AES256_KEY_SIZE:
			if (iv) { // IV implies CBC block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
			}
			break;

		default:
			r = -4;
			goto exit;
	}
	if (!r) {
		r = -5;
		goto exit;
	}

	// Disable padding
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	plen = 0;
	r = EVP_DecryptUpdate(ctx, plaintext, &plen, ciphertext, clen);
	if (!r) {
		r = -6;
		goto exit;
	}

	plen2 = 0;
	r = EVP_DecryptFinal_ex(ctx, plaintext + plen, &plen2);
	if (!r) {
		r = -7;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	EVP_CIPHER_CTX_free(ctx);

	return r;
}

int crypto_aes_encrypt_ctr(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	int clen;
	int clen2;

	// IV/nonce is required for CTR mode
	if (!iv) {
		return -1;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -2;
		goto exit;
	}

	switch (key_len) {
		case AES128_KEY_SIZE:
			r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
			break;

		case AES192_KEY_SIZE:
			r = EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv);
			break;

		case AES256_KEY_SIZE:
			r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
			break;

		default:
			r = -3;
			goto exit;
	}
	if (!r) {
		r = -4;
		goto exit;
	}

	// Disable padding
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	clen = 0;
	r = EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
	if (!r) {
		r = -5;
		goto exit;
	}

	clen2 = 0;
	r = EVP_EncryptFinal_ex(ctx, ciphertext + clen, &clen2);
	if (!r) {
		r = -6;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	EVP_CIPHER_CTX_free(ctx);

	return r;
}
