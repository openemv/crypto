/**
 * @file crypto_rand.c
 * @brief Random data crypto helper functions using OpenSSL
 *
 * Copyright 2021-2023, 2025 Leon Lynch
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
#include "crypto_mem.h"

#include <string.h>

#include <openssl/rand.h>

void crypto_rand(void* buf, size_t len)
{
	RAND_bytes(buf, len);
}

void crypto_rand_non_zero(void* buf, size_t len)
{
	uint8_t* ptr = buf;
	uint8_t data[32];
	size_t data_len = sizeof(data);

	while (len) {
		RAND_bytes(data, sizeof(data));

		// Use only non-zero bytes
		while (len && data_len) {
			if (data[--data_len]) {
				ptr[--len] = data[data_len];
			}
		}
	}

	crypto_cleanse(data, sizeof(data));
}

int crypto_rand_byte(unsigned int min, unsigned int max)
{
	uint8_t data[32];
	size_t data_len = sizeof(data);
	unsigned int range;
	unsigned int limit;
	unsigned int max_tries = 500;

	if (min >= max) {
		return -1;
	}
	if (min > 255 || max > 255) {
		return -2;
	}

	// Determine largest multiple of the range size that is less than or equal
	// to the byte range size of 256 (because 0 - 255). This multiple is the
	// rejection sampling limit and all numbers equal to or larger than this
	// limit must be rejected such that a modulus of the remaining numbers is
	// a uniform distribution of the desired range.
	range = max - min + 1; // No risk of overflow because both are < 256
	limit = 255 - (255 % range);

	do {
		crypto_rand(data, sizeof(data));

		while (data_len) {
			unsigned int x = data[--data_len];
			if (x < limit) {
				crypto_cleanse(data, sizeof(data));

				// Reject samples greater than or equal to the limit
				return (x % range) + min;
			}
		}
	} while (--max_tries < 0);

	// Failed to generate number within range
	crypto_cleanse(data, sizeof(data));
	return -3;
}
