/***************************************************************************************************************************************
 * FILE NAME: sha1.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-09-04
 *
 * CONTENT: Implements the SHA1 hash algorithm and its corresponding HMAC-SHA1 function in accordance with the 
 *          NIST specifications (FIPS PUB 180-4) and (FIPS PUB 198-1).
 *
 **************************************************************************************************************************************/
    
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "shalib.h"
#include "sha1.h"

#define BLOCK_SIZE 64       /* defines the size of a block in BYTES                                     */ 
#define WORD_SIZE 4         /* defines the size of a word in BYTES                                      */
#define HASH_SIZE 5         /* defines the size of the hash in number of 32-bit INTEGERS                */



/************************************************************************************************************/


void SHA1_Compute(struct sha_word_pointer *p, uint32_t *hash)
{
    const uint32_t H_init[] = {0x67452301,       /* Initial SHA1 hash vector */
                               0xefcdab89,
                               0x98badcfe,
                               0x10325476,
                               0xc3d2e1f0};  
    uint32_t H[HASH_SIZE];
    uint64_t N;
    int i;

    /* Initiate the hash */

    for (i = 0; i < HASH_SIZE; i++)
        H[i] = H_init[i];

    /* Iterate the hash */

    N = p->tot_byte_size/BLOCK_SIZE;
    for (i = 0; i < N; i++)
        SHA1_Iterate_Hash(p, H);

    /* Store final hash */

    for (i = 0; i < HASH_SIZE; i++)
        hash[i] = H[i];
}

/*********************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1_Concat
 *
 * PURPOSE: Takes as an argument a collection of char arrays, performs a virtual concatenation of these arrays in
 *          the order they appear, implements the SHA1 algorithm on the concatenated array and stores the resulting hash.
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * strings             char**          I       the pointer to the char* array containing the pointers to the char arrays 
 *                                             to be hashed as a concatenation
 * nr_of_strings       uint64_t        I       the number of char arrays in the concatenation
 * strings_byte_size   uint64_t*       I       pointer to the uint64_t array containing the size in bytes of each char array 
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : void
 *
 *********************************************************************************************************************************/

void SHA1_Concat(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash)
{
    int i;                          
    uint64_t concat_byte_size;                   /* the size in bytes of the total string concatenation     */
    unsigned char pad[BLOCK_SIZE + 9];           /* the pad                                                 */
    struct sha_word_pointer p;                   /* the word pointer                                        */

    /* Initiate the word pointer */

    Set_Zero(&p);
    p.strings = strings;
    p.nr_of_strings = nr_of_strings;
    p.strings_byte_size = strings_byte_size;

    /* Calculate the total byte-size of the string concatenation and set the pad */

    concat_byte_size = 0;
    for (i = 0; i < nr_of_strings; i++)
        concat_byte_size = concat_byte_size + strings_byte_size[i];
    Set_64Byte_Pad(&p, pad, concat_byte_size);

    /* Compute the hash */

    SHA1_Compute(&p, hash);
}

/********************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1
 *
 * PURPOSE: Takes as an argument a char array and computes its SHA1 hash
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * text                char*           I       the pointer to the char array containing the text to be hashed
 * text_byte_size      uint64_t*       I       the byte size of the char array to be hashed
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : void
 *                                    
 *********************************************************************************************************************************/

void SHA1(char *text, uint64_t text_byte_size, uint32_t *hash)
{
    uint64_t text_byte_size_[1];
    text_byte_size_[0] = text_byte_size;
    SHA1_Concat(&text, 1, text_byte_size_, hash);
}

/*******************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1_File
 *
 * PURPOSE: Takes as an argument a file name and computes the SHA1 hash of its content
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * filename            char*           I       pointer to char array containing the file name
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : int
 *
 *******************************************************************************************************************************/

int SHA1_File(char *filename, uint32_t *hash)
{
    int exit_status;                            /* exit status                          */
    FILE* fp;                                   /* pointer to the file to be hashed     */
    uint64_t file_byte_size;                    /* the size of the file in bytes        */
    unsigned char pad[BLOCK_SIZE + 9];          /* the pad                              */
    struct sha_word_pointer p;                  /* the word pointer                     */


    /* Open the file and determine its size */ 

    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        exit_status = EXIT_FAILURE;
        goto end;
    }
    fseek(fp, 0L, SEEK_END);
    file_byte_size = ftell(fp);
    rewind(fp);

    /* Initiate the word pointer */

    Set_Zero(&p);
    p.fp = fp;
    p.file_byte_size = file_byte_size;

    /* Set the pad */

    Set_64Byte_Pad(&p, pad, file_byte_size);
  
    /* Compute the hash */

    SHA1_Compute(&p, hash);

    /* Return exit status */

    exit_status = EXIT_SUCCESS;

    end:
    return exit_status;
} 

/*******************************************************************************************************************************
 *
 * FUNCTION NAME: HMAC_SHA1
 *
 * PURPOSE: Takes as an argument a string and a key and computes the corresponding HMAC-SHA1 digest
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * key                 char*           I       the pointer to the char array containing the key
 * key_size            unsigned int    I       the key size in bytes
 * text                char*           I       the pointer to the char array containing the text to be digested with the key
 * text_size           uint64_t        I       the byte size of the char array containing the text
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting digest is to be stored
 *
 * RETURN VALUE : void
 *
 *******************************************************************************************************************************/

void HMAC_SHA1(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest)
{
    HMAC32(key, key_size, text, text_size, digest, SHA1, SHA1_Concat, HASH_SIZE);
}


