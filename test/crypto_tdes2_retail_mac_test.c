/**
 * @file crypto_tdes2_retail_mac_test.c
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

struct mac_test_t {
	uint8_t data[64]; // Max test data length
	size_t data_len;
	uint8_t mac[DES_RETAIL_MAC_SIZE];
};

// ISO 9797-1:2011 Annex B.4 examples using MAC algorithm 3 and padding method 1
static const uint8_t retail_mac_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static const struct mac_test_t mac_tests[] = {
	{
		"Now is the time for all ",
		24,
		{ 0xA1, 0xC7, 0x2E, 0x74 },
	},
	{
		"Now is the time for it",
		22,
		{ 0x2E, 0x2B, 0x14, 0x28 },
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
	uint8_t mac[DES_RETAIL_MAC_SIZE];

	// Test X9.19 retail mac
	for (size_t i = 0; i < sizeof(mac_tests) / sizeof(mac_tests[0]); ++i) {
		r = crypto_tdes2_retail_mac(
			retail_mac_key,
			mac_tests[i].data,
			mac_tests[i].data_len,
			mac
		);
		if (r) {
			fprintf(stderr, "crypto_tdes2_retail_mac() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(mac, mac_tests[i].mac, sizeof(mac_tests[i].mac)) != 0) {
			fprintf(stderr, "X9.19 MAC test %zu failed\n", i);
			print_buf("mac", mac, sizeof(mac));
			print_buf("expected", mac_tests[i].mac, sizeof(mac_tests[i].mac));
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
