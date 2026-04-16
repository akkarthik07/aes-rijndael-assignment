/*
 * rijndael.h - Header file for the Rijndael (AES) implementation.
 * 
 * Author: Karthik | Student No: A00046404
 * 
 * This header file exposes the types and functions needed to encrypt and decrypt 
 * data using the AES block cipher.
 * 
 * Supported block sizes:
 *  - AES_BLOCK_128: 128-bit block size (16 bytes)
 *  - AES_BLOCK_256: 256-bit block size (32 bytes)
 *  - AES_BLOCK_512: 512-bit block size (64 bytes)
 * 
 * Note: The AES algorithm is typically defined for a fixed block size of 128 bits.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

typedef enum {
  AES_BLOCK_128,
  AES_BLOCK_256,
  AES_BLOCK_512
} aes_block_size_t;

unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size);

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(
    unsigned char *plaintext,
    unsigned char *key,
    aes_block_size_t block_size);
unsigned char *aes_decrypt_block(
    unsigned char *ciphertext,
    unsigned char *key,
    aes_block_size_t block_size);

#endif
