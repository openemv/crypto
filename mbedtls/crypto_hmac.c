/**
 * @file crypto_hmac.c
 * @brief Hash-based Message Authentication Code (HMAC) crypto helper functions
 *        using MbedTLS
 *
 * Copyright 2022 Leon Lynch
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

#include <mbedtls/md.h>

int crypto_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	int r;
	mbedtls_md_context_t ctx;

	if (!key || !key_len || !hmac) {
		return 1;
	}
	if (buf_len && !buf) {
		return 2;
	}

	mbedtls_md_init(&ctx);
	r = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_md_hmac_starts(&ctx, key, key_len);
	if (r) {
		r = -2;
		goto exit;
	}

	r = mbedtls_md_hmac_update(&ctx, buf, buf_len);
	if (r) {
		r = -3;
		goto exit;
	}

	r = mbedtls_md_hmac_finish(&ctx, hmac);
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_md_free(&ctx);

	return r;
}
