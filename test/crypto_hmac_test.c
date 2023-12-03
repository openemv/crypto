/**
 * @file crypto_hmac_test.c
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct hmac_test_t {
	const char* input;
	uint8_t hmac[HMAC_SHA256_SIZE];
};

// ISO 9797-2:2011 Annex B.3.4 examples using MAC algorithm 2 and dedicated hash-function 4 (SHA-256)
static const uint8_t hmac_sha256_key1[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};
static const struct hmac_test_t hmac_sha256_tests1[] = {
	{
		"",
		{
			0xE8, 0xA0, 0x65, 0x37, 0xF0, 0x96, 0xCC, 0xF1, 0xA3, 0xC4, 0x25, 0xA5, 0x6C, 0xEA, 0x05, 0x40,
			0x72, 0xC4, 0xA8, 0xDB, 0x67, 0xBD, 0x28, 0xCF, 0xB0, 0x2F, 0xBE, 0xAF, 0x84, 0xB3, 0x5F, 0x6C,
		},
	},

	{
		"a",
		{
			0xDD, 0xAB, 0xFD, 0xF4, 0x6C, 0xE9, 0x33, 0x11, 0x86, 0x8B, 0x72, 0x75, 0xE0, 0x57, 0x30, 0xAD,
			0x3E, 0x23, 0x19, 0x2A, 0x57, 0x5C, 0xC2, 0x91, 0xAE, 0x37, 0x85, 0x28, 0x9B, 0x94, 0xA2, 0xF3,
		},
	},

	{
		"abc",
		{
			0x02, 0x58, 0x1E, 0xA3, 0x9A, 0x6C, 0xF2, 0xD7, 0x52, 0x79, 0x3F, 0xD7, 0x82, 0xCF, 0xB9, 0xCF,
			0x96, 0x5B, 0xE7, 0x2B, 0x32, 0xB3, 0x22, 0xC9, 0x55, 0x1D, 0x03, 0x51, 0x06, 0x45, 0xFB, 0x31,
		},
	},

	{
		"message digest",
		{
			0x1F, 0x12, 0x28, 0x8F, 0x42, 0xF4, 0x26, 0x61, 0x34, 0x9E, 0x5D, 0xB7, 0x41, 0xCE, 0x19, 0xF3,
			0xB8, 0xC3, 0xA8, 0x14, 0x9F, 0xD4, 0xB8, 0x98, 0x12, 0x37, 0xFA, 0x20, 0x0F, 0xEB, 0x10, 0x4F,
		},
	},

	{
		"abcdefghijklmnopqrstuvwxyz",
		{
			0xEA, 0x4A, 0x04, 0xE7, 0x6E, 0xEC, 0x57, 0xD6, 0x90, 0x60, 0x98, 0xAF, 0xA7, 0xAE, 0x02, 0x64,
			0x07, 0x2C, 0x09, 0xF0, 0xDB, 0x34, 0x26, 0x9B, 0x11, 0x7C, 0x68, 0xC3, 0xED, 0x98, 0x9C, 0x5E,
		},
	},

	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{
			0x6E, 0xB6, 0x83, 0x21, 0x83, 0x05, 0xA8, 0x62, 0xA1, 0xC1, 0xEF, 0xBA, 0x04, 0xA2, 0xA6, 0x2D,
			0xC4, 0xEC, 0x27, 0x88, 0x6D, 0x3C, 0x79, 0xAF, 0xF7, 0xC4, 0x93, 0xC2, 0xD6, 0xDF, 0xB0, 0x80,
		},
	},

	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		{
			0x6D, 0xC6, 0x4A, 0xC5, 0xC5, 0xF1, 0x97, 0xEB, 0x54, 0x63, 0x47, 0x4A, 0xA6, 0xB3, 0x29, 0xDA,
			0x9D, 0x5B, 0x3C, 0x6A, 0x33, 0x24, 0xB1, 0x47, 0x46, 0x9E, 0x06, 0xF2, 0x1E, 0xB5, 0x3C, 0x41,
		},
	},

	{
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		{
			0x8F, 0x4B, 0x41, 0x75, 0x27, 0xDA, 0x95, 0x33, 0x40, 0x8D, 0x95, 0x95, 0x1E, 0xD6, 0x50, 0x45,
			0x25, 0xC9, 0x68, 0x3B, 0x45, 0x63, 0x7B, 0x24, 0x6C, 0xE2, 0x5C, 0x99, 0xAC, 0xC6, 0x46, 0x98,
		},
	},
};

// ISO 9797-2:2011 Annex B.3.4 examples using MAC algorithm 2 and dedicated hash-function 4 (SHA-256)
static const uint8_t hmac_sha256_key2[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static const struct hmac_test_t hmac_sha256_tests2[] = {
	{
		"",
		{
			0xDC, 0xC3, 0xC8, 0x12, 0x36, 0xAA, 0xD9, 0x20, 0x43, 0xD1, 0x47, 0x8D, 0xF7, 0x92, 0x6E, 0x78,
			0x20, 0x5F, 0x7B, 0xBD, 0x0C, 0x30, 0x01, 0x85, 0x4B, 0xF9, 0x08, 0x72, 0x61, 0xAC, 0xCE, 0x47,
		},
	},

	{
		"a",
		{
			0xAE, 0xE1, 0x54, 0xDC, 0xF8, 0x35, 0x68, 0x24, 0x8D, 0xC2, 0x28, 0xC8, 0xC3, 0x51, 0x3E, 0x9B,
			0xEE, 0xA2, 0x68, 0xB4, 0x97, 0x9F, 0xF1, 0x7C, 0xDE, 0x5B, 0xE4, 0x84, 0xF4, 0x91, 0x9D, 0xDA,
		},
	},

	{
		"abc",
		{
			0xC3, 0xB5, 0x3B, 0x98, 0x97, 0xD7, 0x21, 0x97, 0xB2, 0x40, 0xF0, 0x87, 0x15, 0xE5, 0xC8, 0x30,
			0x88, 0x6F, 0xE2, 0xF2, 0xEF, 0xC2, 0xE5, 0xA8, 0xAC, 0xD9, 0xD5, 0x40, 0x50, 0x98, 0x86, 0x3B,
		},
	},

	{
		"message digest",
		{
			0x60, 0xCD, 0x78, 0xCA, 0xED, 0x2C, 0xC9, 0xBD, 0x3F, 0x5B, 0xDA, 0x6A, 0xAA, 0x81, 0x59, 0x6B,
			0x55, 0x55, 0x66, 0x60, 0xB1, 0x9A, 0x2D, 0xF2, 0xFF, 0x6C, 0x48, 0xF8, 0x9C, 0x52, 0xCD, 0x7E,
		},
	},

	{
		"abcdefghijklmnopqrstuvwxyz",
		{
			0x62, 0x83, 0xD8, 0xBA, 0x03, 0x1E, 0xE5, 0x2E, 0x2D, 0x7E, 0xBA, 0x96, 0x28, 0x70, 0x25, 0xF1,
			0x61, 0xA5, 0x21, 0x9E, 0xF1, 0xFB, 0x59, 0xCE, 0xBE, 0x61, 0x33, 0x00, 0x7B, 0x35, 0xA1, 0x46,
		},
	},

	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{
			0x3B, 0xB6, 0x25, 0x76, 0x8D, 0x09, 0x00, 0x71, 0x0F, 0x0E, 0xF7, 0xE8, 0x54, 0x99, 0x0B, 0xBB,
			0xA3, 0x5A, 0xA9, 0xB7, 0xBD, 0x4B, 0x01, 0x33, 0x65, 0x6D, 0x29, 0x09, 0x92, 0xA9, 0xBF, 0x79,
		},
	},

	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		{
			0x98, 0xFF, 0x69, 0xD0, 0x04, 0x8F, 0xF5, 0x52, 0x84, 0x3C, 0xB8, 0xD5, 0xDC, 0x68, 0x6E, 0xB2,
			0xFE, 0xC3, 0x60, 0x0D, 0x66, 0x4A, 0x46, 0x4F, 0x7B, 0x88, 0xF7, 0x28, 0x9C, 0xC4, 0x1A, 0x78,
		},
	},

	{
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		{
			0x58, 0x93, 0xF4, 0xAD, 0x6C, 0xEB, 0xB8, 0x5B, 0xB9, 0x0C, 0xD4, 0x10, 0x7B, 0xF8, 0x5E, 0xEE,
			0xBA, 0xB6, 0x21, 0xC6, 0xEE, 0xB4, 0xEC, 0x48, 0x77, 0x80, 0xA4, 0x5D, 0xED, 0x09, 0xF5, 0xB2,
		},
	},
};

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(void)
{
	int r;
	uint8_t hmac[HMAC_SHA256_SIZE];

	// Test HMAC-SHA256 with key1
	for (size_t i = 0; i < sizeof(hmac_sha256_tests1) / sizeof(hmac_sha256_tests1[0]); ++i) {
		r = crypto_hmac_sha256(
			hmac_sha256_key1,
			sizeof(hmac_sha256_key1),
			hmac_sha256_tests1[i].input,
			strlen(hmac_sha256_tests1[i].input),
			hmac
		);
		if (r) {
			fprintf(stderr, "crypto_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(hmac, hmac_sha256_tests1[i].hmac, sizeof(hmac_sha256_tests1[i].hmac)) != 0) {
			fprintf(stderr, "HMAC-SHA256 test %zu failed\n", i);
			print_buf("hmac", hmac, sizeof(hmac));
			print_buf("expected", hmac_sha256_tests1[i].hmac, sizeof(hmac_sha256_tests1[i].hmac));
			r = 1;
			goto exit;
		}
	}

	// Test HMAC-SHA256 with key2
	for (size_t i = 0; i < sizeof(hmac_sha256_tests2) / sizeof(hmac_sha256_tests2[0]); ++i) {
		r = crypto_hmac_sha256(
			hmac_sha256_key2,
			sizeof(hmac_sha256_key2),
			hmac_sha256_tests2[i].input,
			strlen(hmac_sha256_tests2[i].input),
			hmac
		);
		if (r) {
			fprintf(stderr, "crypto_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(hmac, hmac_sha256_tests2[i].hmac, sizeof(hmac_sha256_tests2[i].hmac)) != 0) {
			fprintf(stderr, "HMAC-SHA256 test %zu failed\n", i);
			print_buf("hmac", hmac, sizeof(hmac));
			print_buf("expected", hmac_sha256_tests2[i].hmac, sizeof(hmac_sha256_tests2[i].hmac));
			r = 1;
			goto exit;
		}
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
