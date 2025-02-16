/**
 * @file crypto_sha.h
 * @brief Secure Hash Algorithm (SHA) crypto helper functions
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

#ifndef OPENEMV_CRYPTO_SHA_H
#define OPENEMV_CRYPTO_SHA_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define SHA1_SIZE (20) ///< SHA-1 digest size in bytes
#define SHA256_SIZE (32) ///< SHA256 digest size in bytes

/// SHA-1 context
typedef void* crypto_sha1_ctx_t;

/// SHA-256 context
typedef void* crypto_sha256_ctx_t;

/**
 * Create new SHA-1 context
 *
 * @remark See NIST FIPS 180-2
 *
 * @param ctx SHA-1 context
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha1_init(crypto_sha1_ctx_t* ctx);

/**
 * Update SHA-1 computation
 *
 * @param ctx SHA-1 context
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha1_update(
	crypto_sha1_ctx_t* ctx,
	const void* buf,
	size_t buf_len
);

/**
 * Finish SHA-1 computation and provide digest output
 *
 * @param ctx SHA-1 context
 * @param digest Digest output of length @ref SHA1_SIZE
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha1_finish(
	crypto_sha1_ctx_t* ctx,
	void* digest
);

/**
 * Free SHA-1 context
 *
 * @param ctx SHA-1 context
 */
void crypto_sha1_free(crypto_sha1_ctx_t* ctx);

/**
 * Create new SHA-256 context
 *
 * @remark See NIST FIPS 180-2
 *
 * @param ctx SHA-256 context
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha256_init(crypto_sha256_ctx_t* ctx);

/**
 * Update SHA-256 computation
 *
 * @param ctx SHA-256 context
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha256_update(
	crypto_sha256_ctx_t* ctx,
	const void* buf,
	size_t buf_len
);

/**
 * Finish SHA-256 computation and provide digest output
 *
 * @param ctx SHA-256 context
 * @param digest Digest output of length @ref SHA256_SIZE
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_sha256_finish(
	crypto_sha256_ctx_t* ctx,
	void* digest
);

/**
 * Free SHA-256 context
 *
 * @param ctx SHA-256 context
 */
void crypto_sha256_free(crypto_sha256_ctx_t* ctx);

__END_DECLS

#endif
