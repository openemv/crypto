/**
 * @file crypto_mem.h
 * @brief Memory-related crypto helper functions
 *
 * Copyright 2021-2022 Leon Lynch
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

#ifndef OPENEMV_CRYPTO_MEM_H
#define OPENEMV_CRYPTO_MEM_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

/**
 * Cleanse (zero) buffer
 *
 * @note This function is intended to be used instead of memset() for clearing
 *       sensitive buffers, typically at the end of functions, when the
 *       compiler may choose to optimise memset() away.
 *
 * @param buf Pointer to buffer
 * @param len Length of buffer in bytes
 */
void crypto_cleanse(void* buf, size_t len) __attribute__((noinline));

/**
 * Securely compare buffers
 *
 * @note This function is intended to be used instead of memcmp() for
 *       comparing sensitive buffers such that the performance of the
 *       comparison is always relative to the provided length, and not
 *       relative to the byte(s) that differ. This mitigates timing attacks.
 *
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Number of bytes to compare
 * @return Zero if bytes match. Non-zero if bytes differ.
 */
int crypto_memcmp_s(const void* a, const void* b, size_t len) __attribute__((noinline));

/**
 * Left shift buffer
 *
 * @param buf Pointer to buffer
 * @param len Length of buffer in bytes
 * @return Carry bit after left shift
 */
int crypto_lshift(void* buf, size_t len);

/**
 * XOR buffers. This function will perform the equivalent of <tt>x ^= y</tt>
 *
 * @param x Pointer to first buffer
 * @param y Pointer to second buffer
 * @param len Number of bytes to XOR
 */
void crypto_xor(void* x, const void* y, size_t len);

__END_DECLS

#endif
