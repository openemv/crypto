/**
 * @file crypto_tdes_cmac_test.c
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

#include "crypto_tdes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct cmac_test_t {
	uint8_t data[64]; // Max test data length
	size_t data_len;
	uint8_t cmac[DES_CMAC_SIZE];
};

// NIST SP 800-38B Appendix D CMAC-TDES examples using triple length key
// See http://csrc.nist.gov/groups/ST/toolkit/examples.html
static const uint8_t cmac_tdes3_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
	0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
};
static const struct cmac_test_t cmac_tdes3_tests[] = {
	{
		{},
		0,
		{ 0x7D, 0xB0, 0xD3, 0x7D, 0xF9, 0x36, 0xC5, 0x50 },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		},
		16,
		{ 0x30, 0x23, 0x9C, 0xF1, 0xF5, 0x2E, 0x66, 0x09 },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
			0xAE, 0x2D, 0x8A, 0x57,
		},
		20,
		{ 0x6C, 0x9F, 0x3E, 0xE4, 0x92, 0x3F, 0x6B, 0xE2 },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
			0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		},
		32,
		{ 0x99, 0x42, 0x9B, 0xD0, 0xBF, 0x79, 0x04, 0xE5 },
	},
};

// NIST SP 800-38B Appendix D CMAC-TDES examples using double length key
// See http://csrc.nist.gov/groups/ST/toolkit/examples.html
static const uint8_t cmac_tdes2_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
};
static const struct cmac_test_t cmac_tdes2_tests[] = {
	{
		{},
		0,
		{ 0x79, 0xCE, 0x52, 0xA7, 0xF7, 0x86, 0xA9, 0x60 },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		},
		16,
		{ 0xCC, 0x18, 0xA0, 0xB7, 0x9A, 0xF2, 0x41, 0x3B },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
			0xAE, 0x2D, 0x8A, 0x57,
		},
		20,
		{ 0xC0, 0x6D, 0x37, 0x7E, 0xCD, 0x10, 0x19, 0x69 },
	},

	{
		{
			0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
			0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		},
		32,
		{ 0x9C, 0xD3, 0x35, 0x80, 0xF9, 0xB6, 0x4D, 0xFB },
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
	uint8_t cmac[DES_CMAC_SIZE];

	// Test CMAC for TDES3
	for (size_t i = 0; i < sizeof(cmac_tdes3_tests) / sizeof(cmac_tdes3_tests[0]); ++i) {
		r = crypto_tdes_cmac(
			cmac_tdes3_key,
			sizeof(cmac_tdes3_key),
			cmac_tdes3_tests[i].data,
			cmac_tdes3_tests[i].data_len,
			cmac
		);
		if (r) {
			fprintf(stderr, "crypto_tdes_cmac() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(cmac, cmac_tdes3_tests[i].cmac, sizeof(cmac_tdes3_tests[i].cmac)) != 0) {
			fprintf(stderr, "CMAC-TDES3 test %zu failed\n", i);
			print_buf("cmac", cmac, sizeof(cmac));
			print_buf("expected", cmac_tdes3_tests[i].cmac, sizeof(cmac_tdes3_tests[i].cmac));
			r = 1;
			goto exit;
		}
	}

	// Test CMAC for TDES2
	for (size_t i = 0; i < sizeof(cmac_tdes2_tests) / sizeof(cmac_tdes2_tests[0]); ++i) {
		r = crypto_tdes_cmac(
			cmac_tdes2_key,
			sizeof(cmac_tdes2_key),
			cmac_tdes2_tests[i].data,
			cmac_tdes2_tests[i].data_len,
			cmac
		);
		if (r) {
			fprintf(stderr, "crypto_tdes_cmac() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(cmac, cmac_tdes2_tests[i].cmac, sizeof(cmac_tdes2_tests[i].cmac)) != 0) {
			fprintf(stderr, "CMAC-TDES2 test %zu failed\n", i);
			print_buf("cmac", cmac, sizeof(cmac));
			print_buf("expected", cmac_tdes2_tests[i].cmac, sizeof(cmac_tdes2_tests[i].cmac));
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
