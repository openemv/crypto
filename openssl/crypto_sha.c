/**
 * @file crypto_sha.c
 * @brief Secure Hash Algorithm (SHA) crypto helper functions using OpenSSL
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

#include <openssl/evp.h>

int crypto_sha1_init(crypto_sha1_ctx_t* ctx)
{
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}

	*ctx = EVP_MD_CTX_new();
	if (!*ctx) {
		return -1;
	}
	mdctx = *ctx;

	ret = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	if (ret != 1) {
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
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (buf_len && !buf) {
		return 3;
	}
	mdctx = *ctx;

	ret = EVP_DigestUpdate(mdctx, buf, buf_len);
	if (ret != 1) {
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
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (!digest) {
		return 3;
	}
	mdctx = *ctx;

	ret = EVP_DigestFinal_ex(mdctx, digest, NULL);
	if (ret != 1) {
		crypto_sha1_free(ctx);
		return -1;
	}

	return 0;
}

void crypto_sha1_free(crypto_sha1_ctx_t* ctx)
{
	if (!ctx || !*ctx) {
		return;
	}

	EVP_MD_CTX_free(*ctx);
	*ctx = NULL;
}

int crypto_sha256_init(crypto_sha256_ctx_t* ctx)
{
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}

	*ctx = EVP_MD_CTX_new();
	if (!*ctx) {
		return -1;
	}
	mdctx = *ctx;

	ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	if (ret != 1) {
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
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (buf_len && !buf) {
		return 3;
	}
	mdctx = *ctx;

	ret = EVP_DigestUpdate(mdctx, buf, buf_len);
	if (ret != 1) {
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
	EVP_MD_CTX* mdctx;
	int ret;

	if (!ctx) {
		return 1;
	}
	if (!*ctx) {
		return 2;
	}
	if (!digest) {
		return 3;
	}
	mdctx = *ctx;

	ret = EVP_DigestFinal_ex(mdctx, digest, NULL);
	if (ret != 1) {
		crypto_sha256_free(ctx);
		return -1;
	}

	return 0;
}

void crypto_sha256_free(crypto_sha256_ctx_t* ctx)
{
	if (!ctx || !*ctx) {
		return;
	}

	EVP_MD_CTX_free(*ctx);
	*ctx = NULL;
}
