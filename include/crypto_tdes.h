/**
 * @file crypto_tdes.h
 * @brief DES and TDES crypto helper functions
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

#ifndef OPENEMV_CRYPTO_TDES_H
#define OPENEMV_CRYPTO_TDES_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define DES_BLOCK_SIZE (8) ///< DES block size in bytes
#define DES_KEY_SIZE (8) ///< DES key size in bytes
#define TDES2_KEY_SIZE (DES_KEY_SIZE * 2) ///< Double length triple DES key size in bytes
#define TDES3_KEY_SIZE (DES_KEY_SIZE * 3) ///< Triple length triple DES key size in bytes

/**
 * Encrypt using single length DES-CBC
 *
 * @param key Key of length @ref DES_KEY_SIZE
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_des_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using single length DES-ECB
 *
 * @param key Key of length @ref DES_KEY_SIZE
 * @param plaintext Plaintext to encrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_des_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	return crypto_des_encrypt(key, NULL, plaintext, DES_BLOCK_SIZE, ciphertext);
}

/**
 * Encrypt using TDES-CBC
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_tdes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using TDES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param plaintext Plaintext to encrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output of length @ref DES_BLOCK_SIZE.
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes_encrypt_ecb(const void* key, size_t key_len, const void* plaintext, void* ciphertext)
{
	return crypto_tdes_encrypt(key, key_len, NULL, plaintext, DES_BLOCK_SIZE, ciphertext);
}

/**
 * Encrypt using double length TDES-CBC
 *
 * @param key Key
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes2_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	return crypto_tdes_encrypt(key, TDES2_KEY_SIZE, iv, plaintext, plen, ciphertext);
}

/**
 * Encrypt using double length TDES-ECB
 *
 * @param key Key
 * @param plaintext Plaintext to encrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes2_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	return crypto_tdes2_encrypt(key, NULL, plaintext, DES_BLOCK_SIZE, ciphertext);
}

/**
 * Decrypt using TDES-CBC
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_tdes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Decrypt using TDES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output of length @ref DES_BLOCK_SIZE.
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext)
{
	return crypto_tdes_decrypt(key, key_len, NULL, ciphertext, DES_BLOCK_SIZE, plaintext);
}

/**
 * Decrypt using double length TDES-CBC
 *
 * @param key Key
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes2_decrypt(const void* key, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	return crypto_tdes_decrypt(key, TDES2_KEY_SIZE, iv, ciphertext, clen, plaintext);
}

/**
 * Decrypt using double length TDES-ECB
 *
 * @param key Key
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_tdes2_decrypt_ecb(const void* key, const void* ciphertext, void* plaintext)
{
	return crypto_tdes2_decrypt(key, NULL, ciphertext, DES_BLOCK_SIZE, plaintext);
}

__END_DECLS

#endif
