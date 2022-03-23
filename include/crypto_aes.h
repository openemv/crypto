/**
 * @file crypto_aes.h
 * @brief AES crypto helper functions
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

#ifndef OPENEMV_CRYPTO_AES_H
#define OPENEMV_CRYPTO_AES_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define AES_BLOCK_SIZE (16) ///< AES block size in bytes
#define AES128_KEY_SIZE (16) ///< AES-128 key size in bytes
#define AES192_KEY_SIZE (24) ///< AES-192 key size in bytes
#define AES256_KEY_SIZE (32) ///< AES-256 key size in bytes

/**
 * Encrypt using AES-CBC
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_aes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using AES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param plaintext Plaintext to encrypt. Must be of length @ref AES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_aes_encrypt_ecb(const void* key, size_t key_len, const void* plaintext, void* ciphertext)
{
	return crypto_aes_encrypt(key, key_len, NULL, plaintext, AES_BLOCK_SIZE, ciphertext);
}

/**
 * Decrypt using AES-CBC
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_aes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Decrypt using AES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_aes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext)
{
	return crypto_aes_decrypt(key, key_len, NULL, ciphertext, AES_BLOCK_SIZE, plaintext);
}

__END_DECLS

#endif
