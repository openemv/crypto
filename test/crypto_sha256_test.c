/**
 * @file crypto_sha256_test.c
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct sha256_test_t {
	const char* input;
	uint8_t digest[SHA256_SIZE];
};

static const struct sha256_test_t sha256_tests[] = {
	// FIPS 180-2, Appendix B.1
	{
		"abc",
		{
			0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
			0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
			0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
			0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
		},
	},

	// FIPS 180-2, Appendix B.2
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{
			0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
			0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
			0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
			0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1,
		},
	},
};

// FIPS 180-2, Appendix B.3
static const uint8_t sha256_long_test_digest[SHA256_SIZE] = {
	0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
	0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
	0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
	0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0,
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

	for (size_t i = 0; i < sizeof(sha256_tests) / sizeof(sha256_tests[0]); ++i) {
		crypto_sha256_ctx_t ctx = (void*)0xdeadbeef;
		uint8_t digest[SHA256_SIZE];

		r = crypto_sha256_init(&ctx);
		if (r) {
			fprintf(stderr, "crypto_sha256_init() failed; r=%d\n", r);
			goto exit;
		}

		r = crypto_sha256_update(&ctx, sha256_tests[i].input, strlen(sha256_tests[i].input));
		if (r) {
			fprintf(stderr, "crypto_sha256_update() failed; r=%d\n", r);
			goto exit;
		}

		memset(digest, 0, sizeof(digest));;
		r = crypto_sha256_finish(&ctx, digest);
		if (r) {
			fprintf(stderr, "crypto_sha256_finish() failed; r=%d\n", r);
			goto exit;
		}

		if (memcmp(digest, sha256_tests[i].digest, sizeof(sha256_tests[i].digest)) != 0) {
			fprintf(stderr, "SHA-256 test %zu failed\n", i);
			print_buf("digest", digest, sizeof(digest));
			print_buf("expected", sha256_tests[i].digest, sizeof(sha256_tests[i].digest));
			r = 1;
			goto exit;
		}

		crypto_sha256_free(&ctx);
	}

	// FIPS 180-2, Appendix B.3
	{
		crypto_sha256_ctx_t ctx = (void*)0xdeadbeef;
		uint8_t digest[SHA256_SIZE];
		char buf[16] = "aaaaaaaaaaaaaaaa";
		size_t i = 1000000;

		r = crypto_sha256_init(&ctx);
		if (r) {
			fprintf(stderr, "crypto_sha256_init() failed; r=%d\n", r);
			goto exit;
		}

		do {
			for (size_t buf_len = 1; buf_len <= sizeof(buf); ++buf_len) {
				if (i < buf_len) {
					break;
				}

				r = crypto_sha256_update(&ctx, buf, buf_len);
				if (r) {
					fprintf(stderr, "crypto_sha256_update() failed; r=%d\n", r);
					goto exit;
				}

				// Advance
				i -= buf_len;
			}
		} while (i);
		if (i >= sizeof(buf)) {
			fprintf(stderr, "Unexpected loop failure; i=%zu\n", i);
			goto exit;
		}

		// Last block
		r = crypto_sha256_update(&ctx, buf, i);
		if (r) {
			fprintf(stderr, "crypto_sha256_update() failed; r=%d\n", r);
			goto exit;
		}

		memset(digest, 0, sizeof(digest));;
		r = crypto_sha256_finish(&ctx, digest);
		if (r) {
			fprintf(stderr, "crypto_sha256_finish() failed; r=%d\n", r);
			goto exit;
		}

		if (memcmp(digest, sha256_long_test_digest, sizeof(sha256_long_test_digest)) != 0) {
			fprintf(stderr, "SHA-256 long test failed\n");
			print_buf("digest", digest, sizeof(digest));
			print_buf("expected", sha256_long_test_digest, sizeof(sha256_long_test_digest));
			r = 1;
			goto exit;
		}

		crypto_sha256_free(&ctx);
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
