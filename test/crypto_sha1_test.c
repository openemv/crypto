/**
 * @file crypto_sha1_test.c
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

struct sha1_test_t {
	const char* input;
	uint8_t digest[SHA1_SIZE];
};

static const struct sha1_test_t sha1_tests[] = {
	// FIPS 180-2, Appendix A.1
	{
		"abc",
		{
			0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
			0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
			0x9C, 0xD0, 0xD8, 0x9D,
		},
	},

	// FIPS 180-2, Appendix A.2
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{
			0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
			0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
			0xE5, 0x46, 0x70, 0xF1,
		},
	},
};

// FIPS 180-2, Appendix A.3
static const uint8_t sha1_long_test_digest[SHA1_SIZE] = {
	0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4,
	0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31,
	0x65, 0x34, 0x01, 0x6F,
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

	for (size_t i = 0; i < sizeof(sha1_tests) / sizeof(sha1_tests[0]); ++i) {
		crypto_sha1_ctx_t ctx = (void*)0xdeadbeef;
		uint8_t digest[SHA1_SIZE];

		r = crypto_sha1_init(&ctx);
		if (r) {
			fprintf(stderr, "crypto_sha1_init() failed; r=%d\n", r);
			goto exit;
		}

		r = crypto_sha1_update(&ctx, sha1_tests[i].input, strlen(sha1_tests[i].input));
		if (r) {
			fprintf(stderr, "crypto_sha1_update() failed; r=%d\n", r);
			goto exit;
		}

		memset(digest, 0, sizeof(digest));;
		r = crypto_sha1_finish(&ctx, digest);
		if (r) {
			fprintf(stderr, "crypto_sha1_finish() failed; r=%d\n", r);
			goto exit;
		}

		if (memcmp(digest, sha1_tests[i].digest, sizeof(sha1_tests[i].digest)) != 0) {
			fprintf(stderr, "SHA-1 test %zu failed\n", i);
			print_buf("digest", digest, sizeof(digest));
			print_buf("expected", sha1_tests[i].digest, sizeof(sha1_tests[i].digest));
			r = 1;
			goto exit;
		}

		crypto_sha1_free(&ctx);
	}

	// FIPS 180-2, Appendix A.3
	{
		crypto_sha1_ctx_t ctx = (void*)0xdeadbeef;
		uint8_t digest[SHA1_SIZE];
		char buf[16] = "aaaaaaaaaaaaaaaa";
		size_t i = 1000000;

		r = crypto_sha1_init(&ctx);
		if (r) {
			fprintf(stderr, "crypto_sha1_init() failed; r=%d\n", r);
			goto exit;
		}

		do {
			for (size_t buf_len = 1; buf_len <= sizeof(buf); ++buf_len) {
				if (i < buf_len) {
					break;
				}

				r = crypto_sha1_update(&ctx, buf, buf_len);
				if (r) {
					fprintf(stderr, "crypto_sha1_update() failed; r=%d\n", r);
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
		r = crypto_sha1_update(&ctx, buf, i);
		if (r) {
			fprintf(stderr, "crypto_sha1_update() failed; r=%d\n", r);
			goto exit;
		}

		memset(digest, 0, sizeof(digest));;
		r = crypto_sha1_finish(&ctx, digest);
		if (r) {
			fprintf(stderr, "crypto_sha1_finish() failed; r=%d\n", r);
			goto exit;
		}

		if (memcmp(digest, sha1_long_test_digest, sizeof(sha1_long_test_digest)) != 0) {
			fprintf(stderr, "SHA-1 long test failed\n");
			print_buf("digest", digest, sizeof(digest));
			print_buf("expected", sha1_long_test_digest, sizeof(sha1_long_test_digest));
			r = 1;
			goto exit;
		}

		crypto_sha1_free(&ctx);
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
