/**
 * @file crypto_rsa.c
 * @brief RSA crypto helper functions using OpenSSL
 *
 * Copyright 2025 Leon Lynch
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

#include "crypto_rsa.h"

#include <openssl/bn.h>

#include <string.h>

int crypto_rsa_mod_exp(
	const void* mod,
	size_t mod_len,
	const void* exp,
	size_t exp_len,
	const void* input,
	void* output
)
{
	int r;
	BN_CTX* ctx;
	BIGNUM* m = NULL;
	BIGNUM* p = NULL;
	BIGNUM* a = NULL;
	BIGNUM* result = NULL;
	size_t result_len;
	int ret;

	if (!mod || !mod_len ||
		!exp || !exp_len
	) {
		return 1;
	}
	if (!input || !output) {
		return 2;
	}
	memset(output, 0, mod_len);

	ctx = BN_CTX_new();
	if (!ctx) {
		return -1;
	}

	// Copy parameters into big numbers
	m = BN_bin2bn(mod, mod_len, NULL);
	if (!m) {
		r = -2;
		goto exit;
	}
	p = BN_bin2bn(exp, exp_len, NULL);
	if (!p) {
		r = -3;
		goto exit;
	}
	a = BN_bin2bn(input, mod_len, NULL);
	if (!a) {
		r = -4;
		goto exit;
	}

	// Perform modular exponentiation
	result = BN_new();
	ret = BN_mod_exp(result, a, p, m, ctx);
	if (!ret) {
		r = -5;
		goto exit;
	}
	result_len = BN_num_bytes(result);
	if (result_len > mod_len) {
		r = -6;
		goto exit;
	}

	// Copy result
	ret = BN_bn2bin(result, output + mod_len - result_len);
	if (!ret) {
		r = -7;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	BN_free(m);
	BN_free(p);
	BN_free(a);
	BN_free(result);
	BN_CTX_free(ctx);
	return r;
}
