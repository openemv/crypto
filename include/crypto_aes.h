/**
 * @file crypto_aes.h
 * @brief AES crypto helper functions
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

#ifndef OPENEMV_CRYPTO_AES_H
#define OPENEMV_CRYPTO_AES_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define AES_BLOCK_SIZE (16) ///< AES block size in bytes
#define AES128_KEY_SIZE (16) ///< AES-128 key size in bytes
#define AES192_KEY_SIZE (24) ///< AES-192 key size in bytes
#define AES256_KEY_SIZE (32) ///< AES-256 key size in bytes
#define AES_CMAC_SIZE (AES_BLOCK_SIZE) ///< AES CMAC size in bytes
#define AES_KCV_SIZE (5) ///< AES CMAC KCV size in bytes

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
 * @param ciphertext Encrypted output of length @ref AES_BLOCK_SIZE.
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
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref AES_BLOCK_SIZE.
 * @param plaintext Decrypted output of length @ref AES_BLOCK_SIZE.
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_aes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext)
{
	return crypto_aes_decrypt(key, key_len, NULL, ciphertext, AES_BLOCK_SIZE, plaintext);
}

/**
 * Encrypt using AES-CTR
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector / nonce
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int crypto_aes_encrypt_ctr(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Decrypt using AES-CTR
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector / nonce
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int crypto_aes_decrypt_ctr(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	return crypto_aes_encrypt_ctr(key, key_len, iv, ciphertext, clen, plaintext);
}

/**
 * Generate AES CMAC
 *
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @remark See NIST SP 800-38B
 * @remark See IETF RFC 4493
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @param cmac AES-CMAC output of length @ref AES_CMAC_SIZE
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_aes_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* cmac
);

/**
 * Generate AES Key Check Value (KCV) using CMAC approach
 *
 * @remark See ANSI X9.24-1:2017, A.3 CMAC-based Check values
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param kcv Key Check Value output of length @ref AES_KCV_SIZE
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int crypto_aes_kcv(const void* key, size_t key_len, void* kcv);

__END_DECLS

#endif
