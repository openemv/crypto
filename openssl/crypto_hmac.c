/**
 * @file crypto_hmac.c
 * @brief Hash-based Message Authentication Code (HMAC) crypto helper functions
 *        using OpenSSL
 *
 * Copyright (c) 2022 Leon Lynch
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

#include "crypto_hmac.h"

#include <openssl/hmac.h>

#include <string.h>

int crypto_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	unsigned int hmac_len = EVP_MD_size(EVP_sha256());
	unsigned char* ret;

	if (!key || !key_len || !hmac) {
		return 1;
	}
	if (buf_len && !buf) {
		return 2;
	}

	// Ensure that hash length matches HMAC output length
	if (hmac_len != HMAC_SHA256_SIZE) {
		return -1;
	}

	ret = HMAC(EVP_sha256(), key, key_len, buf, buf_len, hmac, &hmac_len);
	if (!ret) {
		return -2;
	}
	if (ret != hmac) {
		return -3;
	}

	return 0;
}
