/**
 * @file crypto_hmac.h
 * @brief Hash-based Message Authentication Code (HMAC) crypto helper functions
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

#ifndef OPENEMV_CRYPTO_HMAC_H
#define OPENEMV_CRYPTO_HMAC_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define HMAC_SHA256_SIZE (32) ///< HMAC-SHA256 digest size in bytes

/**
 * Generate HMAC-SHA256
 *
 * @remark See ISO 9797-2:2011 MAC algorithm 2
 * @remark See NIST FIPS 198-1
 * @remark See IETF RFC 2104
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @param hmac HMAC output of length @ref HMAC_SHA256_SIZE
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
);

__END_DECLS

#endif
