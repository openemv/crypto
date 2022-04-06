/**
 * @file crypto_mem.c
 * @brief Memory-related crypto helper functions
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

#include "crypto_mem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

__attribute__((noinline))
void crypto_cleanse(void* buf, size_t len)
{
	memset(buf, 0, len);

	// From GCC documentation:
	// If the function does not have side effects, there are optimizations
	// other than inlining that cause function calls to be optimized away,
	// although the function call is live. To keep such calls from being
	// optimized away, put...
	__asm__ ("");
}

__attribute__((noinline))
int crypto_memcmp_s(const void* a, const void* b, size_t len)
{
	int r = 0;
	const volatile uint8_t* buf_a = a;
	const volatile uint8_t* buf_b = b;

	for (size_t i = 0; i < len; ++i) {
		r |= buf_a[i] ^ buf_b[i];
	}

	return !!r;
}

int crypto_lshift(void* buf, size_t len)
{
	uint8_t* ptr = buf;
	uint8_t lsb;

	ptr += (len - 1);
	lsb = 0x00;
	while (len--) {
		uint8_t msb;

		msb = *ptr & 0x80;
		*ptr <<= 1;
		*ptr |= lsb;
		--ptr;
		lsb = msb >> 7;
	}

	// Return carry bit
	return lsb;
}

void crypto_xor(void* x, const void* y, size_t len)
{
	uint8_t* buf_x = x;
	const uint8_t* buf_y = y;

	for (size_t i = 0; i < len; ++i) {
		*buf_x ^= *buf_y;
		++buf_x;
		++buf_y;
	}
}
