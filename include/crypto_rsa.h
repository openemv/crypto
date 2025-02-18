/**
 * @file crypto_rsa.h
 * @brief RSA crypto helper functions
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

#ifndef OPENEMV_CRYPTO_RSA_H
#define OPENEMV_CRYPTO_RSA_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

/**
 * Perform RSA modular exponentiation
 *
 * @remark IETF RFC 8017, PKCS#1
 *
 * @param mod Modulus (most significant byte first)
 * @param mod_len Modulus length in bytes
 * @param exp Exponent (most significant byte first)
 * @param exp_len Exponent length in bytes
 * @param input Input of length @p mod_len
 * @param output Output of length @p mod_len
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_rsa_mod_exp(
	const void* mod,
	size_t mod_len,
	const void* exp,
	size_t exp_len,
	const void* input,
	void* output
);

__END_DECLS

#endif
