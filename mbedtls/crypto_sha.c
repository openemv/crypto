/**
 * @file crypto_sha.c
 * @brief Secure Hash Algorithm (SHA) crypto helper functions using MbedTLS
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

#include "crypto_sha.h"

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
// For mbedtls_*_ret() functions
#undef MBEDTLS_DEPRECATED_WARNING
#include <mbedtls/compat-2.x.h>
#endif

#include <stdlib.h>

int crypto_sha1_init(crypto_sha1_ctx_t* ctx)
{
	int r;
	mbedtls_sha1_context* c;

	if (!ctx) {
		return 1;
	}

	*ctx = malloc(sizeof(mbedtls_sha1_context));
	if (!*ctx) {
		return -1;
	}
	c = *ctx;

	mbedtls_sha1_init(c);
	r = mbedtls_sha1_starts_ret(c);
	if (r) {
		crypto_sha1_free(ctx);
		return -2;
	}

	return 0;
}

int crypto_sha1_update(
	crypto_sha1_ctx_t* ctx,
	const void* buf,
	size_t buf_len
)
{
	int r;
	mbedtls_sha1_context* c;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (buf_len && !buf) {
		return 3;
	}
	c = *ctx;

	r = mbedtls_sha1_update_ret(c, buf, buf_len);
	if (r) {
		crypto_sha1_free(ctx);
		return -1;
	}

	return 0;
}

int crypto_sha1_finish(
	crypto_sha1_ctx_t* ctx,
	void* digest
)
{
	int r;
	mbedtls_sha1_context* c;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (!digest) {
		return 3;
	}
	c = *ctx;

	r = mbedtls_sha1_finish_ret(c, digest);
	crypto_sha1_free(ctx);
	if (r) {
		return -1;
	}

	return 0;
}

void crypto_sha1_free(crypto_sha1_ctx_t* ctx)
{
	if (!ctx || !*ctx) {
		return;
	}

	mbedtls_sha1_free(*ctx);
	free(*ctx);
	*ctx = NULL;
}

int crypto_sha256_init(crypto_sha256_ctx_t* ctx)
{
	int r;
	mbedtls_sha256_context* c;

	if (!ctx) {
		return 1;
	}

	*ctx = malloc(sizeof(mbedtls_sha256_context));
	if (!*ctx) {
		return -1;
	}
	c = *ctx;

	mbedtls_sha256_init(c);
	r = mbedtls_sha256_starts_ret(c, 0);
	if (r) {
		crypto_sha256_free(ctx);
		return -2;
	}

	return 0;
}

int crypto_sha256_update(
	crypto_sha256_ctx_t* ctx,
	const void* buf,
	size_t buf_len
)
{
	int r;
	mbedtls_sha256_context* c;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (buf_len && !buf) {
		return 3;
	}
	c = *ctx;

	r = mbedtls_sha256_update_ret(c, buf, buf_len);
	if (r) {
		crypto_sha256_free(ctx);
		return -1;
	}

	return 0;
}

int crypto_sha256_finish(
	crypto_sha256_ctx_t* ctx,
	void* digest
)
{
	int r;
	mbedtls_sha256_context* c;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (!digest) {
		return 3;
	}
	c = *ctx;

	r = mbedtls_sha256_finish_ret(c, digest);
	crypto_sha256_free(ctx);
	if (r) {
		return -1;
	}

	return 0;
}

void crypto_sha256_free(crypto_sha256_ctx_t* ctx)
{
	if (!ctx || !*ctx) {
		return;
	}

	mbedtls_sha256_free(*ctx);
	free(*ctx);
	*ctx = NULL;
}
