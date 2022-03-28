/**
 * @file crypto_rand.c
 * @brief Random data crypto helper functions using MbedTLS
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

#include "crypto_rand.h"

#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

void crypto_rand(void* buf, size_t len)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

void crypto_rand_non_zero(void* buf, size_t len)
{
	uint8_t* ptr = buf;
	uint8_t data[32];
	size_t data_len = sizeof(data);

	while (len) {
		crypto_rand(data, sizeof(data));

		// Use only non-zero bytes
		while (len && data_len) {
			if (data[--data_len]) {
				ptr[--len] = data[data_len];
			}
		}

		memset(data, 0, sizeof(data));

	}
}
