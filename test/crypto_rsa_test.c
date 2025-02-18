/**
 * @file crypto_rsa_test.c
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct rsa_test_t {
	const uint8_t* mod;
	size_t mod_len;
	const uint8_t* exp;
	size_t exp_len;
	const uint8_t* input;
	const uint8_t* output;
};

static const struct rsa_test_t rsa_tests[] = {
	{
		// Modulus
		(uint8_t[]) {
			0x6B, 0xEE, 0xD8, 0xBC, 0x39, 0x03, 0xF6, 0x56,
			0x28, 0xB8, 0xF0, 0x72, 0xEE, 0xA0, 0x37, 0x90,
			0xF5, 0x3D, 0x08, 0x01, 0x8B, 0xA9, 0xB6, 0x49,
			0x0A, 0xE8, 0xFE, 0x05, 0x25, 0xC9, 0xA2, 0x90,
			0xDB, 0x41, 0x1D, 0x7A, 0xE1, 0x64, 0xC9, 0x48,
			0xFE, 0xB1, 0xF2, 0x68, 0xDF, 0xBD, 0x0A, 0x67,
		},
		48, // 384-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		},
		// Output
		(uint8_t[]) {
			0x21, 0x61, 0x52, 0x38, 0x5F, 0xA0, 0x2E, 0x80,
			0x54, 0x67, 0xDF, 0xDA, 0x93, 0x5E, 0x67, 0xAF,
			0x44, 0xD0, 0xB9, 0x56, 0x87, 0xDE, 0xDB, 0x07,
			0xAD, 0x07, 0x27, 0x36, 0x43, 0x5A, 0x21, 0x77,
			0x75, 0x5B, 0xD5, 0x91, 0xA4, 0x94, 0xAE, 0x8B,
			0xD1, 0x24, 0xD1, 0xF0, 0x9B, 0x65, 0xAD, 0x71,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xb1, 0x8f, 0x26, 0x85, 0xbc, 0x88, 0xad, 0xbc,
			0x61, 0x03, 0xf0, 0x63, 0x22, 0x0f, 0x1e, 0x81,
			0x44, 0x47, 0xac, 0x42, 0xc8, 0xf4, 0xa0, 0x75,
			0xfa, 0xe5, 0xad, 0x42, 0xb0, 0x70, 0x53, 0x5f,
			0x28, 0x5e, 0xac, 0xa9, 0xf3, 0x74, 0xa2, 0x20,
			0x32, 0x36, 0x5e, 0xe3, 0x9d, 0x3b, 0x7d, 0x1d,
			0xf0, 0xb8, 0x6f, 0xcf, 0x8d, 0x2f, 0x35, 0xcb,
			0xa4, 0xe1, 0xda, 0x0e, 0x44, 0x3f, 0x34, 0xaf,
			0x09, 0xb7, 0x8a, 0x35, 0x59, 0xb9, 0x48, 0x5a,
			0x3c, 0x05, 0xe4, 0x42, 0x26, 0x4b, 0x6c, 0xcd,
			0x6d, 0x6a, 0x00, 0x9e, 0xd2, 0x20, 0x83, 0x28,
			0x8a, 0x64, 0x14, 0xd8, 0x05, 0xa7, 0x69, 0x1e,
			0xef, 0xd7, 0xb5, 0xff, 0x80, 0x62, 0x4a, 0x68,
			0x5d, 0x1a, 0x56, 0x8c, 0xbf, 0xa3, 0x4e, 0xe6,
			0x47, 0x64, 0xe8, 0x97, 0x4d, 0x67, 0x62, 0xa5,
			0x8f, 0xed, 0x42, 0x9d, 0x9e, 0x97, 0x63, 0xf1,
		},
		128, // 1024-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		// Output
		(uint8_t[]) {
			0x09, 0xa9, 0x2e, 0x0e, 0xbc, 0xd8, 0x9c, 0xbe,
			0x49, 0x10, 0xcf, 0xa8, 0x58, 0x82, 0x6b, 0x07,
			0x55, 0x83, 0xde, 0x74, 0x6c, 0x4b, 0x54, 0xcb,
			0xc2, 0x45, 0x90, 0x0a, 0xb3, 0xc5, 0xbc, 0xb8,
			0x7b, 0xd9, 0x13, 0x17, 0xe5, 0x33, 0xc8, 0x43,
			0x31, 0x80, 0x9f, 0x2a, 0xe5, 0xab, 0xdc, 0xd1,
			0x31, 0x07, 0x67, 0x77, 0xd3, 0xe5, 0x6f, 0x62,
			0x4b, 0x99, 0x0b, 0x31, 0x6e, 0x67, 0xd3, 0x55,
			0x71, 0xe5, 0xec, 0x0e, 0x9f, 0xba, 0x3d, 0x37,
			0xb7, 0xda, 0x89, 0xda, 0xae, 0xd4, 0x17, 0x2e,
			0x75, 0x06, 0x8b, 0x64, 0xb5, 0x39, 0x38, 0xf0,
			0x92, 0x64, 0x44, 0x56, 0xdf, 0x9e, 0xda, 0x64,
			0x58, 0xeb, 0x47, 0x3a, 0x9b, 0xd1, 0x87, 0x9b,
			0xb2, 0x7d, 0xe7, 0x6f, 0x11, 0xc5, 0xc4, 0xe5,
			0x06, 0x04, 0xf0, 0x0a, 0xb4, 0xf2, 0xdf, 0x70,
			0xce, 0x9d, 0xd7, 0xbf, 0xc8, 0x15, 0xe8, 0xfc,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xF0, 0xC4, 0x2D, 0xB8, 0x48, 0x6F, 0xEB, 0x95,
			0x95, 0xD8, 0xC7, 0x8F, 0x90, 0x8D, 0x04, 0xA9,
			0xB6, 0xC8, 0xC7, 0x7A, 0x36, 0x10, 0x5B, 0x1B,
			0xF2, 0x75, 0x53, 0x77, 0xA6, 0x89, 0x3D, 0xC4,
			0x38, 0x3C, 0x54, 0xEC, 0x6B, 0x52, 0x62, 0xE5,
			0x68, 0x8E, 0x5F, 0x9D, 0x9D, 0xD1, 0x64, 0x97,
			0xD0, 0xE3, 0xEA, 0x83, 0x3D, 0xEE, 0x2C, 0x8E,
			0xBC, 0xD1, 0x43, 0x83, 0x89, 0xFC, 0xCA, 0x8F,
			0xED, 0xE7, 0xA8, 0x8A, 0x81, 0x25, 0x7E, 0x8B,
			0x27, 0x09, 0xC4, 0x94, 0xD4, 0x2F, 0x72, 0x3D,
			0xEC, 0x2E, 0x0B, 0x5C, 0x09, 0x73, 0x1C, 0x55,
			0x0D, 0xCC, 0x9D, 0x7E, 0x75, 0x25, 0x89, 0x89,
			0x1C, 0xBB, 0xC3, 0x02, 0x13, 0x07, 0xDD, 0x91,
			0x8E, 0x10, 0x0B, 0x34, 0xC0, 0x14, 0xA5, 0x59,
			0xE0, 0xE1, 0x82, 0xAF, 0xB2, 0x1A, 0x72, 0xB3,
			0x07, 0xCC, 0x39, 0x5D, 0xEC, 0x99, 0x57, 0x47,
		},
		128, // 1024-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
		},
		// Output
		(uint8_t[]) {
			0x50, 0x5B, 0x09, 0xBD, 0x5D, 0x0E, 0x66, 0xD7,
			0xC8, 0x82, 0x9F, 0x5B, 0x47, 0x3E, 0xD3, 0x4D,
			0xB5, 0xCF, 0xDB, 0xB5, 0xD5, 0x8C, 0xE7, 0x83,
			0x29, 0xC8, 0xBF, 0x85, 0x20, 0xE4, 0x86, 0xD3,
			0xC4, 0xCF, 0x9B, 0x70, 0xC6, 0x34, 0x65, 0x94,
			0x35, 0x80, 0x80, 0xF4, 0x3F, 0x47, 0xEE, 0x86,
			0x3C, 0xFA, 0xF2, 0xA2, 0xE5, 0xF0, 0x3D, 0x1E,
			0x13, 0xD6, 0xFE, 0xC5, 0x7D, 0xFB, 0x1D, 0x55,
			0x22, 0x24, 0xC4, 0x61, 0xDA, 0x41, 0x1C, 0xFE,
			0x5D, 0x0B, 0x05, 0xBA, 0x87, 0x7E, 0x3A, 0x42,
			0xF6, 0xDE, 0x4D, 0xA4, 0x6A, 0x96, 0x5C, 0x9B,
			0x69, 0x5E, 0xE2, 0xD5, 0x0E, 0x40, 0x08, 0x94,
			0x06, 0x1C, 0xB0, 0xA2, 0x1C, 0xA3, 0xA5, 0x24,
			0xB4, 0x07, 0xE9, 0xFF, 0xBA, 0x87, 0xFC, 0x96,
			0x6B, 0x3B, 0xA9, 0x45, 0x90, 0x84, 0x9A, 0xEB,
			0x90, 0x8A, 0xAF, 0xF4, 0xC7, 0x19, 0xC2, 0xE4,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xa8, 0xb3, 0xb2, 0x84, 0xaf, 0x8e, 0xb5, 0x0b,
			0x38, 0x70, 0x34, 0xa8, 0x60, 0xf1, 0x46, 0xc4,
			0x91, 0x9f, 0x31, 0x87, 0x63, 0xcd, 0x6c, 0x55,
			0x98, 0xc8, 0xae, 0x48, 0x11, 0xa1, 0xe0, 0xab,
			0xc4, 0xc7, 0xe0, 0xb0, 0x82, 0xd6, 0x93, 0xa5,
			0xe7, 0xfc, 0xed, 0x67, 0x5c, 0xf4, 0x66, 0x85,
			0x12, 0x77, 0x2c, 0x0c, 0xbc, 0x64, 0xa7, 0x42,
			0xc6, 0xc6, 0x30, 0xf5, 0x33, 0xc8, 0xcc, 0x72,
			0xf6, 0x2a, 0xe8, 0x33, 0xc4, 0x0b, 0xf2, 0x58,
			0x42, 0xe9, 0x84, 0xbb, 0x78, 0xbd, 0xbf, 0x97,
			0xc0, 0x10, 0x7d, 0x55, 0xbd, 0xb6, 0x62, 0xf5,
			0xc4, 0xe0, 0xfa, 0xb9, 0x84, 0x5c, 0xb5, 0x14,
			0x8e, 0xf7, 0x39, 0x2d, 0xd3, 0xaa, 0xff, 0x93,
			0xae, 0x1e, 0x6b, 0x66, 0x7b, 0xb3, 0xd4, 0x24,
			0x76, 0x16, 0xd4, 0xf5, 0xba, 0x10, 0xd4, 0xcf,
			0xd2, 0x26, 0xde, 0x88, 0xd3, 0x9f, 0x16, 0xfb,
		},
		128, // 1024-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		// Output
		(uint8_t[]) {
			0x08, 0x7d, 0x5b, 0x70, 0xfa, 0x91, 0x58, 0xeb,
			0x9f, 0x3d, 0x72, 0x2a, 0xba, 0xf8, 0x8a, 0xbf,
			0x11, 0x43, 0x79, 0xa0, 0x1e, 0x69, 0xb5, 0x60,
			0x0e, 0xc7, 0x4f, 0x14, 0xdd, 0xcd, 0x2c, 0x6d,
			0xde, 0x18, 0x1a, 0x4c, 0x3e, 0xc4, 0xaf, 0x56,
			0x0c, 0xd1, 0xb0, 0xbe, 0x9f, 0xb9, 0x58, 0xc4,
			0xbf, 0x45, 0x10, 0xe8, 0x02, 0xe3, 0x37, 0x5a,
			0x2d, 0x7e, 0x76, 0x3d, 0x33, 0x2f, 0x83, 0xf7,
			0xc6, 0xfb, 0x17, 0xe0, 0x7c, 0x37, 0xa4, 0x8f,
			0x9b, 0x19, 0x87, 0x48, 0xac, 0xe7, 0x3f, 0x89,
			0x7f, 0x8e, 0x5c, 0x63, 0xf9, 0xff, 0x16, 0xcd,
			0xb1, 0x98, 0x34, 0xe1, 0x36, 0x0c, 0x0c, 0x74,
			0x49, 0x45, 0x65, 0x08, 0x2d, 0x77, 0x6b, 0x81,
			0x14, 0xf9, 0x68, 0xa6, 0xfd, 0x0b, 0x5d, 0xa5,
			0x01, 0xd5, 0x40, 0xd2, 0xc8, 0x27, 0x0e, 0x6a,
			0xc6, 0x48, 0xee, 0xa8, 0x67, 0x98, 0xbc, 0xed,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xb2, 0x9a, 0x25, 0x99, 0xe8, 0x04, 0x83, 0x90,
			0x14, 0xa1, 0xef, 0x53, 0x79, 0xae, 0xc6, 0x38,
			0x78, 0x21, 0xde, 0x2c, 0x1b, 0xcf, 0x72, 0x81,
			0x93, 0x72, 0xdf, 0xab, 0x8f, 0x6d, 0x31, 0xa7,
			0x03, 0x96, 0xc1, 0x72, 0x73, 0x90, 0xf7, 0x94,
			0x1b, 0x33, 0x44, 0x56, 0xcd, 0xcd, 0xd6, 0xf9,
			0xe7, 0x77, 0x9b, 0x3e, 0x5c, 0x83, 0x2b, 0xc2,
			0xd3, 0xa4, 0xab, 0xa0, 0x9a, 0x60, 0xad, 0xaf,
			0x52, 0x4b, 0x9a, 0x94, 0xeb, 0xb6, 0xe6, 0xbc,
			0x5d, 0xb8, 0xc5, 0x07, 0xa7, 0x72, 0x9b, 0xd2,
			0x57, 0x92, 0xb1, 0x82, 0x6d, 0x5e, 0x36, 0x06,
			0x91, 0x81, 0x0f, 0x09, 0x36, 0x96, 0xeb, 0x28,
			0x29, 0x6a, 0xc4, 0x49, 0x47, 0x61, 0xf1, 0xf9,
			0xaa, 0x59, 0x46, 0x00, 0x5a, 0xeb, 0x61, 0x1c,
			0xca, 0x52, 0x62, 0x03, 0x04, 0x10, 0xba, 0x2c,
			0xbc, 0x47, 0x1d, 0x72, 0x3d, 0x0c, 0xcf, 0x89,
		},
		128, // 1024-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		// Output
		(uint8_t[]) {
			0x68, 0x87, 0x17, 0xf9, 0xd4, 0x22, 0xa9, 0xa5,
			0xb0, 0xcd, 0x58, 0x8d, 0x47, 0xab, 0x19, 0x6e,
			0xd3, 0x5c, 0xcc, 0xde, 0xbd, 0x26, 0x3f, 0xbc,
			0x10, 0x13, 0xb3, 0xa3, 0xe2, 0xba, 0x8c, 0x68,
			0xd8, 0x2b, 0x6b, 0xc6, 0x5d, 0x19, 0xee, 0xd2,
			0x65, 0x0f, 0xbd, 0x9e, 0x0f, 0xcd, 0x73, 0xba,
			0x32, 0x2c, 0x21, 0x85, 0x6e, 0xe9, 0x9c, 0x5c,
			0x01, 0x4a, 0xe4, 0x91, 0x98, 0xa4, 0x25, 0x21,
			0xb5, 0x27, 0x3a, 0x57, 0x83, 0x8d, 0x8a, 0x06,
			0x7b, 0x8f, 0xad, 0x83, 0x53, 0x0d, 0x62, 0x0c,
			0xd2, 0x2c, 0x76, 0x3f, 0xa7, 0x03, 0xa3, 0x58,
			0x76, 0x9a, 0x58, 0xe0, 0x1a, 0x1d, 0xa9, 0xc6,
			0x9c, 0xa9, 0x8b, 0xd7, 0xee, 0x92, 0x1f, 0xa0,
			0xc9, 0xfb, 0x2e, 0x41, 0xfe, 0x82, 0x95, 0x24,
			0x16, 0x4c, 0x65, 0x48, 0xc6, 0x04, 0x23, 0x83,
			0x66, 0xae, 0x8c, 0x8a, 0x91, 0x0f, 0xdb, 0x9d,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xa7, 0x45, 0x2b, 0xe2, 0x93, 0x42, 0x74, 0x9c,
			0x9b, 0x85, 0x1b, 0xc3, 0x26, 0x8a, 0x77, 0xb0,
			0xda, 0x1d, 0x8e, 0xc3, 0xdb, 0x6d, 0x9d, 0xb6,
			0xe7, 0xc7, 0xc9, 0x7f, 0xf4, 0xa5, 0x88, 0x47,
			0x30, 0x74, 0x6b, 0xd3, 0x72, 0x93, 0x2f, 0x5a,
			0x49, 0xd3, 0x05, 0x2b, 0xb8, 0x3e, 0x09, 0xe9,
			0x44, 0xdb, 0x9c, 0x79, 0xee, 0xab, 0x64, 0x8a,
			0x98, 0xf3, 0x3c, 0xff, 0x3b, 0x79, 0xa6, 0x7e,
			0x09, 0x28, 0xe0, 0x5a, 0x21, 0xd5, 0x64, 0xc4,
			0x3f, 0xf9, 0x81, 0x54, 0x32, 0x75, 0xd7, 0x46,
			0x43, 0xa0, 0x85, 0x83, 0x66, 0xb4, 0x2b, 0xc4,
			0xbd, 0xeb,
		},
		90, // 720-bit
		// Exponent
		(uint8_t[]) { 0x3 },
		1,
		// Input
		(uint8_t[]) {
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x16, 0x16,
		},
		// Output
		(uint8_t[]) {
			0x4a, 0x3b, 0x17, 0x7d, 0x2d, 0xbd, 0x0e, 0x5a,
			0xde, 0x12, 0x84, 0x83, 0xf5, 0x8b, 0x46, 0x05,
			0xff, 0x81, 0xfd, 0x63, 0xcf, 0x8e, 0xcb, 0xfd,
			0xd3, 0x38, 0xff, 0xae, 0x5d, 0xbc, 0xfe, 0x72,
			0x9c, 0xee, 0xa2, 0xd2, 0xaf, 0x3d, 0xaa, 0xb8,
			0x15, 0x7f, 0xe6, 0xf8, 0x6a, 0x0e, 0x41, 0x94,
			0x79, 0x4b, 0xe0, 0x4a, 0x25, 0xd8, 0x06, 0xe8,
			0x8d, 0x18, 0x29, 0x95, 0x96, 0x46, 0x29, 0x76,
			0x0d, 0x2a, 0x7d, 0x45, 0xc4, 0x78, 0x88, 0x27,
			0xa1, 0x5e, 0x21, 0x5c, 0x8b, 0xad, 0xff, 0x03,
			0xaf, 0xb9, 0x2d, 0xfb, 0xd8, 0xaa, 0xd0, 0xd2,
			0x09, 0x56,
		},
	},

	{
		// Modulus
		(uint8_t[]) {
			0xec, 0x03, 0xdc, 0xb1, 0xec, 0xb3, 0x17, 0x29, 0xa4, 0xa4, 0x93, 0x19, 0xf6, 0x61, 0x29, 0x36,
			0xa5, 0x9f, 0xe9, 0xea, 0x86, 0x42, 0x50, 0x05, 0x30, 0x29, 0x91, 0xff, 0x1f, 0x44, 0x6d, 0x97,
			0xa0, 0x46, 0x39, 0x46, 0xf1, 0x35, 0x26, 0x87, 0x93, 0x7b, 0xe3, 0x4e, 0x64, 0x59, 0x8c, 0xe4,
			0x10, 0x74, 0x8d, 0x9f, 0xd1, 0x97, 0x7f, 0x77, 0x92, 0x31, 0xca, 0x45, 0x99, 0x09, 0x19, 0x20,
			0x90, 0xe3, 0xae, 0x59, 0xfa, 0xc2, 0x9d, 0x2e, 0xd3, 0x0a, 0xdc, 0x73, 0x4b, 0x24, 0x72, 0xc6,
			0x54, 0x10, 0x9f, 0x65, 0xde, 0xd6, 0x76, 0x31, 0xfe, 0x0d, 0xa6, 0xe5, 0xd7, 0x35, 0x68, 0x0e,
			0x27, 0x79, 0xbc, 0x46, 0x16, 0x21, 0xaf, 0x57, 0x0c, 0x74, 0x70, 0x13, 0x8a, 0xa4, 0x6c, 0x9e,
			0x5f, 0x88, 0x9b, 0xbc, 0x0c, 0x72, 0xa8, 0xc9, 0x13, 0x45, 0xd8, 0xe8, 0x00, 0xde, 0x87, 0x05,
			0xaf, 0xb4, 0x82, 0xe9, 0xe5, 0x06, 0x1c, 0xd1, 0xcb, 0x0c, 0x8f, 0xf3, 0x28, 0x4d, 0x06, 0x9b,
			0xc5, 0x1d, 0x40, 0x5b, 0x18, 0x98, 0xfd, 0x57, 0xd3, 0x0e, 0xad, 0x4a, 0x64, 0x8e, 0xff, 0x03,
			0x64, 0x53, 0x42, 0xe5, 0xd0, 0x5c, 0x8b, 0xee, 0xd5, 0x1f, 0xfb, 0x03, 0xb0, 0x18, 0xdd, 0x8c,
			0xd1, 0x6e, 0xf5, 0xc8, 0xf0, 0x40, 0xdd, 0x7d, 0x52, 0xbc, 0xf6, 0x29, 0x57, 0xe3, 0x53, 0x52,
			0xaf, 0x45, 0x93, 0x55, 0x8c, 0x02, 0x17, 0x36, 0xa1, 0x4f, 0xa8, 0xde, 0x56, 0x71, 0x1b, 0x74,
			0x1d, 0x9c, 0x7f, 0xc0, 0xa3, 0xb6, 0x31, 0xbf, 0xac, 0x85, 0x8e, 0x3f, 0x64, 0xa6, 0x1c, 0xa1,
			0x90, 0x60, 0xd4, 0x27, 0x63, 0x6b, 0x50, 0xfc, 0x08, 0xb2, 0xa0, 0xde, 0xa6, 0xf0, 0x16, 0x73,
			0x11, 0x3b, 0x9c, 0x09, 0xb6, 0x13, 0x1b, 0x5f, 0x94, 0x5b, 0x7c, 0x3f, 0xdb, 0xb3, 0x08, 0x15,
		},
		256, // 2048-bit
		// Exponent
		(uint8_t[]) { 0x01, 0x00, 0x01 },
		3,
		// Input
		(uint8_t[]) {
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
			0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
			0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
			0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
			0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		// Output
		(uint8_t[]) {
			0x70, 0x49, 0xdb, 0xe5, 0x06, 0x7c, 0xf3, 0xe0, 0x8a, 0x3f, 0x73, 0x5c, 0xf5, 0x1b, 0x64, 0xf1,
			0xcd, 0x92, 0x9e, 0x37, 0x5f, 0x57, 0x33, 0x2f, 0x97, 0x26, 0x81, 0x5a, 0x18, 0xf5, 0x7d, 0xf5,
			0xca, 0xce, 0xff, 0xd0, 0xd9, 0x7f, 0x51, 0x80, 0xf7, 0xdd, 0x06, 0x97, 0xbf, 0x30, 0x30, 0xab,
			0xd6, 0x2a, 0xb4, 0xf5, 0xce, 0x4e, 0xc8, 0x22, 0x7a, 0xd1, 0x6f, 0x9b, 0x75, 0x59, 0xed, 0xac,
			0xee, 0x07, 0x95, 0x59, 0x9a, 0xcc, 0x10, 0x07, 0x69, 0xb9, 0x19, 0x38, 0x76, 0xad, 0x57, 0x43,
			0xf8, 0xf1, 0x5d, 0x58, 0x9b, 0xa6, 0x5e, 0xdc, 0x68, 0x9d, 0x0c, 0x18, 0x41, 0x36, 0x6e, 0x54,
			0x70, 0x54, 0x8f, 0x33, 0x8e, 0x7c, 0xb6, 0x62, 0x96, 0x34, 0x46, 0x13, 0x79, 0x63, 0x63, 0xc8,
			0xc7, 0xb0, 0x7f, 0xa6, 0xae, 0xfb, 0xdd, 0x79, 0x4e, 0x81, 0x7f, 0xb2, 0xa5, 0x3c, 0x1b, 0xa6,
			0x36, 0x5e, 0xd4, 0x0b, 0xaa, 0x16, 0xcd, 0x92, 0xfb, 0x08, 0x5f, 0x42, 0xbe, 0xea, 0xec, 0x08,
			0xf2, 0x9e, 0x02, 0x88, 0xe6, 0xfb, 0xb1, 0xfb, 0xff, 0xc8, 0x21, 0xdd, 0x59, 0xbb, 0xb5, 0xcd,
			0x58, 0x85, 0x8d, 0x2d, 0x66, 0x93, 0x13, 0x55, 0x30, 0x58, 0x6f, 0x87, 0xa7, 0x49, 0x08, 0x74,
			0x56, 0xf7, 0x17, 0x2e, 0x91, 0x53, 0x6f, 0xa8, 0xe3, 0x6e, 0x2e, 0xd9, 0xef, 0x4a, 0x25, 0x0e,
			0x51, 0xa0, 0xa9, 0x4a, 0xb2, 0xa1, 0x19, 0xe3, 0x18, 0x18, 0x58, 0xf8, 0xdd, 0xf4, 0xc6, 0xb1,
			0xcb, 0xa9, 0xe2, 0xc4, 0xd5, 0xa3, 0xc2, 0x2b, 0xd3, 0x51, 0x3c, 0x6f, 0x09, 0xb2, 0x3b, 0xe7,
			0x70, 0x7c, 0x59, 0x40, 0x90, 0x40, 0xd6, 0xc6, 0x0f, 0x9b, 0x4a, 0x52, 0x76, 0x16, 0xde, 0x1e,
			0xd3, 0xe4, 0xbf, 0xb1, 0x11, 0x2e, 0x71, 0xbc, 0x73, 0xf9, 0xd9, 0x52, 0x5a, 0x59, 0x26, 0x90,
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
	void* output = NULL;

	for (size_t i = 0; i < sizeof(rsa_tests) / sizeof(rsa_tests[0]); ++i) {
		output = malloc(rsa_tests[i].mod_len);

		r = crypto_rsa_mod_exp(
			rsa_tests[i].mod,
			rsa_tests[i].mod_len,
			rsa_tests[i].exp,
			rsa_tests[i].exp_len,
			rsa_tests[i].input,
			output
		);
		if (r) {
			fprintf(stderr, "crypto_rsa_mod_exp() failed; r=%d\n", r);
			goto exit;
		}

		if (memcmp(output, rsa_tests[i].output, rsa_tests[i].mod_len) != 0) {
			fprintf(stderr, "RSA test %zu failed\n", i);
			print_buf("output", output, sizeof(rsa_tests[i].mod_len));
			print_buf("expected",rsa_tests[i].output, rsa_tests[i].mod_len);
			r = 1;
			goto exit;
		}

		free(output);
		output = NULL;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	if (output) {
		free(output);
		output = NULL;
	}
	return r;
}
