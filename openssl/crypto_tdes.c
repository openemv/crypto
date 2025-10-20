/**
 * @file crypto_tdes.c
 * @brief DES and TDES crypto helper functions using OpenSSL
 *
 * Copyright 2021-2023 Leon Lynch
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

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

int crypto_des_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* cipher;
#if OPENSSL_VERSION_MAJOR >= 3
	uint8_t key_buf[TDES2_KEY_SIZE];
#endif
	int clen;
	int clen2;

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -3;
		goto exit;
	}
#if OPENSSL_VERSION_MAJOR >= 3
	// OpenSSL 3 has deprecated DES (but not TDES) and moved it to a legacy
	// provider which cannot easily be used without impacting the parent
	// project. Therefore TDES will be used to perform DES instead.
	memcpy(key_buf, key, DES_KEY_SIZE);
	memcpy(key_buf + DES_KEY_SIZE, key, DES_KEY_SIZE);
	if (iv) { // IV implies CBC block mode
		cipher = EVP_des_ede_cbc();
	} else { // No IV implies ECB block mode
		cipher = EVP_des_ede_ecb();
	}
	key = key_buf;
#else
	if (iv) { // IV implies CBC block mode
		cipher = EVP_des_cbc();
	} else { // No IV implies ECB block mode
		cipher = EVP_des_ecb();
	}
#endif
	r = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
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
#if OPENSSL_VERSION_MAJOR >= 3
	OPENSSL_cleanse(key_buf, sizeof(key_buf));
#endif

	return r;
}

int crypto_tdes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	int clen;
	int clen2;

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -3;
		goto exit;
	}

	switch (key_len) {
		case TDES2_KEY_SIZE: // Double length TDES key
			if (iv) { // IV implies CBC block mode
				r = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_EncryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key, NULL);
			}
			break;

		case TDES3_KEY_SIZE: // Triple length TDES key
			if (iv) { // IV implies CBC block mode
				r = EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL);
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

int crypto_tdes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	int r;
	EVP_CIPHER_CTX* ctx;
	int plen;
	int plen2;

	// Ensure that ciphertext length is a multiple of the DES block length
	if ((clen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && clen != DES_BLOCK_SIZE) {
		return -2;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		r = -3;
		goto exit;
	}

	switch (key_len) {
		case TDES2_KEY_SIZE: // Double length TDES key
			if (iv) { // IV implies CBC block mode
				r = EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_DecryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key, NULL);
			}
			break;

		case TDES3_KEY_SIZE: // Triple length TDES key
			if (iv) { // IV implies CBC block mode
				r = EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
			} else { // No IV implies ECB block mode
				r = EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL);
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
