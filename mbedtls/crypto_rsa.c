/**
 * @file crypto_rsa.c
 * @brief RSA crypto helper functions using MbedTLS
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

#include <mbedtls/bignum.h>

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
	mbedtls_mpi N;
	mbedtls_mpi E;
	mbedtls_mpi X;
	mbedtls_mpi result;
	size_t result_len;

	if (!mod || !mod_len ||
		!exp || !exp_len
	) {
		return 1;
	}
	if (!input || !output) {
		return 2;
	}
	memset(output, 0, mod_len);

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&X);
	mbedtls_mpi_init(&result);

	// Copy parameters into big numbers
	r = mbedtls_mpi_read_binary(&N, mod, mod_len);
	if (r) {
		r = -1;
		goto exit;
	}
	r = mbedtls_mpi_read_binary(&E, exp, exp_len);
	if (r) {
		r = -2;
		goto exit;
	}
	r = mbedtls_mpi_read_binary(&X, input, mod_len);
	if (r) {
		r = -3;
		goto exit;
	}

	// Perform modular exponentiation
	r = mbedtls_mpi_exp_mod(&result, &X, &E, &N, NULL);
	if (r) {
		r = -4;
		goto exit;
	}
	result_len = mbedtls_mpi_size(&result);
	if (result_len > mod_len) {
		r = -5;
		goto exit;
	}

	// Copy result
	r = mbedtls_mpi_write_binary(&result, output + mod_len - result_len, result_len);
	if (r) {
		r = -6;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&X);
	mbedtls_mpi_free(&result);

	return r;
}
