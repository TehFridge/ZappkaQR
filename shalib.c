/***************************************************************************************************************************************
 * FILE NAME: shalib.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-09-05
 *
 * CONTENT: Defines methods common to the SHA-algorithms
 *
 **************************************************************************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "shalib.h"

#define TRUE 1
#define FALSE 0 
#define DELIMITER 128


/***************************************************************************************************************************************/

/* The function Set_Zero sets all parameters in the word pointer to zero or NULL depending on their type */ 

void Set_Zero(struct sha_word_pointer *p)
{
    p->array_index = 0;
    p->array_position = 0;
    p->strings = NULL;
    p->nr_of_strings = 0;
    p->strings_byte_size = NULL;
    p->pad = NULL;
    p->pad_position = 0;
    p->pad_byte_size = 0;
    p->is_in_pad = FALSE;
    p->fp = NULL;
    p->file_byte_size = 0;
    p->file_position = 0;
}

/*----------------------------------------------------------------------------------------------------*/

/* The function Set_Pad prepares and sets the pad                     */

void Set_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size, unsigned int BLOCK_SIZE)
{
    int i;                                              /* internal counter variable                               */
    unsigned int nr_of_zeros;                           /* number of zero bytes in the pad                         */ 
    unsigned int pad_byte_size;                         /* the size of the pad                                     */
    uint64_t text_bit_size;                             /* the size in BITS of the text                            */

    /* Calculate the number of zeros in the pad and the pad size */

    if (BLOCK_SIZE == 64) 
        nr_of_zeros = (BLOCK_SIZE - ((text_byte_size + 9) % BLOCK_SIZE)) % BLOCK_SIZE;
    else if (BLOCK_SIZE == 128)
         nr_of_zeros = ((BLOCK_SIZE - ((text_byte_size + 17) % BLOCK_SIZE)) % BLOCK_SIZE) + 8;

    pad_byte_size = 9 + nr_of_zeros;

    /* Set the first byte in the pad equal to the delimiter 10000000b */

    pad[0] = DELIMITER;                                 

    /* Insert the zeros in the pad */

    for (i = 1; i <= nr_of_zeros; i++) 
        pad[i] = 0; 

    /* Insert an 8-byte rep. of the bit-size at the end of the pad */                                

    text_bit_size = 8*text_byte_size;      
    for (i = 0; i < 8; i++)
        pad[pad_byte_size - i - 1] = (text_bit_size >> i*8) & 255;  

    /* Put the pad and related data in the word pointer */  

    p->pad = pad;
    p->pad_position = 0;
    p->pad_byte_size = pad_byte_size;
    p->is_in_pad = FALSE;
    p->tot_byte_size = text_byte_size + pad_byte_size;
}

/***************************************************************************************************************************************
 * 
 *  SECTION: 32-BIT WORD POINTER METHODS
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 64
#define WORD_SIZE 4


/* The function Conv_32Int_To_Word takes a 32-bit integer argument and saves it as a four-byte char array 
   starting at the position specified by the pointer a.                                               */

void Conv_32Int_To_Word(uint32_t i, char *a)
{
    a[0] = (i >> 24) & 255;
    a[1] = (i >> 16) & 255;
    a[2] = (i >> 8) & 255;
    a[3] = i & 255;
}

/* The function Conv_Word_To_32Int is the inverse of Conv_32Int_To_Word */

uint32_t Conv_Word_To_32Int(unsigned char *a)
{
    return a[0] << 24 |
           a[1] << 16 |
           a[2] << 8 |
           a[3];
}

/*-------------------------------------------------------------------------------------------------------------------*/

/* The function Set_64Byte_Pad sets the pad for 64 byte blocks
   Note that pointer with enough allocated memory for the pad must be provided  */

void Set_64Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size)
{
    Set_Pad(p, pad, text_byte_size, BLOCK_SIZE);
}


/*------------------------------------------------------------------------------------------------------------------*/


void Load_String_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the edge of the current string */
    if(p->array_index < p->nr_of_strings && p->array_position + BLOCK_SIZE < p->strings_byte_size[p->array_index])
    {
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int((unsigned char*) &p->strings[p->array_index][p->array_position + WORD_SIZE*i]);

        p->array_position = p->array_position + BLOCK_SIZE;
    }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If there are no more strings, jump into the pad */
            else if (p->array_index == p->nr_of_strings)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is at the end of a string, jump to the next string */
            else if (p->array_position == p->strings_byte_size[p->array_index])
            {
                p->array_index++;
                p->array_position = 0;
            }
            /* If the pointer is still within a string, load the buffer with a byte from the string */
            else if (p->array_index < p->nr_of_strings && p->array_position < p->strings_byte_size[p->array_index])
            {
                p->buffer[i] = (unsigned char) p->strings[p->array_index][p->array_position];
                p->array_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 32-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int(&p->buffer[i*WORD_SIZE]);
    }
}

void Load_File_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the pad */
    if(p->file_position + BLOCK_SIZE < p->file_byte_size)
        {
            for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
                W[i] = (unsigned char) fgetc(p->fp) << 24 |
                       (unsigned char) fgetc(p->fp) << 16 |
                       (unsigned char) fgetc(p->fp) << 8 |
                       (unsigned char) fgetc(p->fp);

            p->file_position = p->file_position + BLOCK_SIZE;
        }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If we have reached the end of the file, jump into the pad */
            else if (p->file_position == p->file_byte_size)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is still within the file, load the buffer with a byte from the file*/
            else if ( p->file_position < p->file_byte_size)
            {
                p->buffer[i] = (unsigned char) fgetc(p->fp);
                p->file_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 32-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int(&p->buffer[i*WORD_SIZE]);
    }
}

/* The function Load_32Int_Buffer advances the position of the word-pointer one block and saves its corresponding 
   integer representation in the array W. */


void Load_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    if (p->fp == NULL)  
        Load_String_32Int_Buffer(p, W);

    else                
        Load_File_32Int_Buffer(p, W);
}

#undef BLOCK_SIZE
#undef WORD_SIZE



/***************************************************************************************************************************************
 * 
 *  SECTION: 64-BIT WORD POINTER METHODS
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 128
#define WORD_SIZE 8


/* The function Conv_64Int_To_Word takes an integer argument and saves it as a four-byte char array 
   starting at the position specified by the pointer a.                                         */

void Conv_64Int_To_Word(uint64_t i, char *a)
{
    a[0] = (i >> 56) & 255;
    a[1] = (i >> 48) & 255;
    a[2] = (i >> 40) & 255;
    a[3] = (i >> 32) & 255;
    a[4] = (i >> 24) & 255;
    a[5] = (i >> 16) & 255;
    a[6] = (i >> 8) & 255;
    a[7] = i & 255;
}

/* The function Conv_Word_To_64Int is the inverse of Conv_64Int_To_Word */

uint64_t Conv_Word_To_64Int(unsigned char *a)
{
    return (uint64_t) a[0] << 56 |
           (uint64_t) a[1] << 48 |
           (uint64_t) a[2] << 40 |
           (uint64_t) a[3] << 32 |
           (uint64_t) a[4] << 24 |
           (uint64_t) a[5] << 16 |
           (uint64_t) a[6] << 8 |
           (uint64_t) a[7];
}

/*-------------------------------------------------------------------------------------------------------------------*/

/* The function Set_128Byte_Pad sets the pad for 128 byte blocks
   Note that pointer with enough allocated memory for the pad must be provided  */

void Set_128Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size)
{
    Set_Pad(p, pad, text_byte_size, BLOCK_SIZE);
}



/*-------------------------------------------------------------------------------------------------------------------*/

void Load_String_64Int_Buffer(struct sha_word_pointer *p, uint64_t *W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the edge of the current string */
    if(p->array_index < p->nr_of_strings && p->array_position + BLOCK_SIZE < p->strings_byte_size[p->array_index])
    {
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int((unsigned char*) &p->strings[p->array_index][p->array_position + WORD_SIZE*i]);

        p->array_position = p->array_position + BLOCK_SIZE;
    }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If there are no more strings, jump into the pad */
            else if (p->array_index == p->nr_of_strings)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is at the end of a string, jump to the next string */
            else if (p->array_position == p->strings_byte_size[p->array_index])
            {
                p->array_index++;
                p->array_position = 0;
            }
            /* If the pointer is still within a string, load the buffer with a byte from the string */
            else if (p->array_index < p->nr_of_strings && p->array_position < p->strings_byte_size[p->array_index])
            {
                p->buffer[i] = (unsigned char) p->strings[p->array_index][p->array_position];
                p->array_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 64-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int(&p->buffer[i*WORD_SIZE]);
    }
}

void Load_File_64Int_Buffer(struct sha_word_pointer *p, uint64_t *W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the pad */
    if(p->file_position + BLOCK_SIZE < p->file_byte_size)
        {
            for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
                W[i] = (uint64_t) fgetc(p->fp) << 56 |
                       (uint64_t) fgetc(p->fp) << 48 |
                       (uint64_t) fgetc(p->fp) << 40 |
                       (uint64_t) fgetc(p->fp) << 32 |
                       (uint64_t) fgetc(p->fp) << 24 |
                       (uint64_t) fgetc(p->fp) << 16 |
                       (uint64_t) fgetc(p->fp) << 8 |
                       (uint64_t) fgetc(p->fp);

            p->file_position = p->file_position + BLOCK_SIZE;
        }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If we have reached the end of the file, jump into the pad */
            else if (p->file_position == p->file_byte_size)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is still within the file, load the buffer with a byte from the file*/
            else if ( p->file_position < p->file_byte_size)
            {
                p->buffer[i] = (unsigned char) fgetc(p->fp);
                p->file_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 64-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int(&p->buffer[i*WORD_SIZE]);
    }
}

/* The function Load_Buffer advances the position of the word-pointer one block and saves its corresponding 
   integer representation in the array W. */


void Load_64Int_Buffer(struct sha_word_pointer *p, uint64_t* W)
{
    if (p->fp == NULL)  
        Load_String_64Int_Buffer(p, W);

    else                
        Load_File_64Int_Buffer(p, W);
}

#undef BLOCK_SIZE
#undef WORD_SIZE


/***************************************************************************************************************************************
 * 
 *  SECTION: 32-BIT HMAC IMPLEMENTATION
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 64
#define WORD_SIZE 4

void HMAC32(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest, void (*SHA)(char *text, uint64_t text_byte_size, uint32_t *hash), void (*SHA_Concat)(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash), unsigned int HASH_SIZE)
{
    int i;                                  /* internal counter variable                                    */
    char key0[BLOCK_SIZE];                  /* array to store the key adjusted to the block size            */
    char key0_xor_ipad[BLOCK_SIZE];         /* array to store the key0 with the ipad added to it            */
    char key0_xor_opad[BLOCK_SIZE];         /* array to store the key0 with the opad added to it            */
    uint32_t hash1[HASH_SIZE];              /* array to store the intermediate hash as integers             */
    char hash1_str[HASH_SIZE * WORD_SIZE];  /* array to store the intermediate hash as a string             */
    char *concat1[2];                       /* pointers to the first concatenation                          */
    char *concat2[2];                       /* pointers to the second concatenation                         */ 
    uint64_t concat1_byte_size[2];          /* the sizes of the strings forming the first concatenation     */
    uint64_t concat2_byte_size[2];          /* the sizes of the strings forming the second concatenation    */


    /* If the key is longer than the block size, hash the key and pad the result with zeros */

    if (key_size > BLOCK_SIZE)
    {
        uint32_t key_hash[HASH_SIZE];       /* array to store the hash of the key */
        SHA(key, key_size, key_hash);

        for(i = 0; i < HASH_SIZE; i++)
            Conv_32Int_To_Word(key_hash[i], &key0[i * WORD_SIZE]);

        for(i = HASH_SIZE * WORD_SIZE; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Otherwise pad the key with zeros */

    if (key_size <= BLOCK_SIZE)
    {
        for(i = 0; i < key_size; i++)
            key0[i] = key[i];

        for(i = key_size; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Add the ipad to the key, concatenate it with the text and hash the result */ 

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_ipad[i] = key0[i] ^ 0x36;

    concat1[0] = key0_xor_ipad;
    concat1[1] = text;
    concat1_byte_size[0] = BLOCK_SIZE;
    concat1_byte_size[1] = text_size;

    SHA_Concat(concat1, 2, concat1_byte_size, hash1);

    /* Convert the intermediate hash to a char array */

    for(i = 0; i < HASH_SIZE; i++)
        Conv_32Int_To_Word(hash1[i], &hash1_str[i * WORD_SIZE]);

    /* Add the opad to the key, concatenate it with the intermediate hash and hash the result */

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_opad[i] = key0[i] ^ 0x5c;

    concat2[0] = key0_xor_opad;
    concat2[1] = hash1_str;
    concat2_byte_size[0] = BLOCK_SIZE;
    concat2_byte_size[1] = HASH_SIZE * WORD_SIZE;

    SHA_Concat(concat2, 2, concat2_byte_size, digest);
}

#undef BLOCK_SIZE
#undef WORD_SIZE

/***************************************************************************************************************************************
 * 
 *  SECTION: 64-BIT HMAC IMPLEMENTATION
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 128
#define WORD_SIZE 8

void HMAC64(char *key, unsigned int key_size, char *text, uint64_t text_size, uint64_t *digest, void (*SHA)(char *text, uint64_t text_byte_size, uint64_t *hash), void (*SHA_Concat)(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint64_t *hash), unsigned int HASH_SIZE)
{
    int i;                                  /* internal counter variable                                    */
    char key0[BLOCK_SIZE];                  /* array to store the key adjusted to the block size            */
    char key0_xor_ipad[BLOCK_SIZE];         /* array to store the key0 with the ipad added to it            */
    char key0_xor_opad[BLOCK_SIZE];         /* array to store the key0 with the opad added to it            */
    uint64_t hash1[HASH_SIZE];              /* array to store the intermediate hash as integers             */
    char hash1_str[HASH_SIZE * WORD_SIZE];  /* array to store the intermediate hash as a string             */
    char *concat1[2];                       /* pointers to the first concatenation                          */
    char *concat2[2];                       /* pointers to the second concatenation                         */ 
    uint64_t concat1_byte_size[2];          /* the sizes of the strings forming the first concatenation     */
    uint64_t concat2_byte_size[2];          /* the sizes of the strings forming the second concatenation    */


    /* If the key is longer than the block size, hash the key and pad the result with zeros */

    if (key_size > BLOCK_SIZE)
    {
        uint64_t key_hash[HASH_SIZE];       /* array to store the hash of the key */
        SHA(key, key_size, key_hash);

        for(i = 0; i < HASH_SIZE; i++)
            Conv_64Int_To_Word(key_hash[i], &key0[i * WORD_SIZE]);

        for(i = HASH_SIZE * WORD_SIZE; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Otherwise pad the key with zeros */

    if (key_size <= BLOCK_SIZE)
    {
        for(i = 0; i < key_size; i++)
            key0[i] = key[i];

        for(i = key_size; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Add the ipad to the key, concatenate it with the text and hash the result */ 

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_ipad[i] = key0[i] ^ 0x36;

    concat1[0] = key0_xor_ipad;
    concat1[1] = text;
    concat1_byte_size[0] = BLOCK_SIZE;
    concat1_byte_size[1] = text_size;

    SHA_Concat(concat1, 2, concat1_byte_size, hash1);

    /* Convert the intermediate hash to a char array */

    for(i = 0; i < HASH_SIZE; i++)
        Conv_64Int_To_Word(hash1[i], &hash1_str[i * WORD_SIZE]);

    /* Add the opad to the key, concatenate it with the intermediate hash and hash the result */

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_opad[i] = key0[i] ^ 0x5c;

    concat2[0] = key0_xor_opad;
    concat2[1] = hash1_str;
    concat2_byte_size[0] = BLOCK_SIZE;
    concat2_byte_size[1] = HASH_SIZE * WORD_SIZE;

    SHA_Concat(concat2, 2, concat2_byte_size, digest);
}


#undef BLOCK_SIZE
#undef WORD_SIZE


/***************************************************************************************************************************************
 * 
 *  SECTION: SHA ITERATION FUNCTIONS
 *
 **************************************************************************************************************************************/

/* The function SHA1_Iterate_Hash implements the SHA1 hash iteration function. 
   See the NIST documentation (FIPS PUB 180-4) for details. 
   This part of the code has been optimized for speed */


void SHA1_Iterate_Hash(struct sha_word_pointer *p, uint32_t *H)
{
    #define Rot_Left(t, x) (((x) << t) | ((x) >> (32 - t)))
    #define Ch(x, y, z) ((x & y) ^ (~x & z))
    #define Parity(x, y, z) (x ^ y ^ z)
    #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

    #define F1(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Ch(b, c, d) + 0x5a827999 + x;         \
        b =  Rot_Left(30, b);                                       \
    }

    #define F2(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Parity(b, c, d) + 0x6ed9eba1 + x;     \
        b = Rot_Left(30, b);                                        \
    }

    #define F3(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Maj(b, c, d) + 0x8f1bbcdc + x;        \
        b = Rot_Left(30, b);                                        \
    }

    #define F4(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Parity(b, c, d) + 0xca62c1d6 + x;     \
        b = Rot_Left(30, b);                                        \
    }

    #define U(i)  (W[i] = Rot_Left(1, W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), W[i])

    uint32_t W[80], a, b, c, d, e;

    Load_32Int_Buffer(p, W);

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    F1(a, b, c, d, e, W[0]);
    F1(e, a, b, c, d, W[1]);
    F1(d, e, a, b, c, W[2]);
    F1(c, d, e, a, b, W[3]);
    F1(b, c, d, e, a, W[4]);
    F1(a, b, c, d, e, W[5]);
    F1(e, a, b, c, d, W[6]);
    F1(d, e, a, b, c, W[7]);
    F1(c, d, e, a, b, W[8]);
    F1(b, c, d, e, a, W[9]);
    F1(a, b, c, d, e, W[10]);
    F1(e, a, b, c, d, W[11]);
    F1(d, e, a, b, c, W[12]);
    F1(c, d, e, a, b, W[13]);
    F1(b, c, d, e, a, W[14]);
    F1(a, b, c, d, e, W[15]);
    F1(e, a, b, c, d, U(16));
    F1(d, e, a, b, c, U(17));
    F1(c, d, e, a, b, U(18));
    F1(b, c, d, e, a, U(19));

    F2(a, b, c, d, e, U(20));
    F2(e, a, b, c, d, U(21));
    F2(d, e, a, b, c, U(22));
    F2(c, d, e, a, b, U(23));
    F2(b, c, d, e, a, U(24));
    F2(a, b, c, d, e, U(25));
    F2(e, a, b, c, d, U(26));
    F2(d, e, a, b, c, U(27));
    F2(c, d, e, a, b, U(28));
    F2(b, c, d, e, a, U(29));
    F2(a, b, c, d, e, U(30));
    F2(e, a, b, c, d, U(31));
    F2(d, e, a, b, c, U(32));
    F2(c, d, e, a, b, U(33));
    F2(b, c, d, e, a, U(34));
    F2(a, b, c, d, e, U(35));
    F2(e, a, b, c, d, U(36));
    F2(d, e, a, b, c, U(37));
    F2(c, d, e, a, b, U(38));
    F2(b, c, d, e, a, U(39));

    F3(a, b, c, d, e, U(40));
    F3(e, a, b, c, d, U(41));
    F3(d, e, a, b, c, U(42));
    F3(c, d, e, a, b, U(43));
    F3(b, c, d, e, a, U(44));
    F3(a, b, c, d, e, U(45));
    F3(e, a, b, c, d, U(46));
    F3(d, e, a, b, c, U(47));
    F3(c, d, e, a, b, U(48));
    F3(b, c, d, e, a, U(49));
    F3(a, b, c, d, e, U(50));
    F3(e, a, b, c, d, U(51));
    F3(d, e, a, b, c, U(52));
    F3(c, d, e, a, b, U(53));
    F3(b, c, d, e, a, U(54));
    F3(a, b, c, d, e, U(55));
    F3(e, a, b, c, d, U(56));
    F3(d, e, a, b, c, U(57));
    F3(c, d, e, a, b, U(58));
    F3(b, c, d, e, a, U(59));

    F4(a, b, c, d, e, U(60));
    F4(e, a, b, c, d, U(61));
    F4(d, e, a, b, c, U(62));
    F4(c, d, e, a, b, U(63));
    F4(b, c, d, e, a, U(64));
    F4(a, b, c, d, e, U(65));
    F4(e, a, b, c, d, U(66));
    F4(d, e, a, b, c, U(67));
    F4(c, d, e, a, b, U(68));
    F4(b, c, d, e, a, U(69));
    F4(a, b, c, d, e, U(70));
    F4(e, a, b, c, d, U(71));
    F4(d, e, a, b, c, U(72));
    F4(c, d, e, a, b, U(73));
    F4(b, c, d, e, a, U(74));
    F4(a, b, c, d, e, U(75));
    F4(e, a, b, c, d, U(76));
    F4(d, e, a, b, c, U(77));
    F4(c, d, e, a, b, U(78));
    F4(b, c, d, e, a, U(79));

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
}

/****************************************************************************************************************/

/* The function SHA256_Iterate_Hash implements the SHA256 hash iteration function. 
   See the NIST documentation (FIPS PUB 180-4) for details.                         */


void SHA256_Iterate_Hash(struct sha_word_pointer *p, uint32_t *H)
{
    #define Rot_Left(t, x) (((x) << t) | ((x) >> (32 - t)))
    #define Rot_Right(t, x) (((x) << (32 - t)|((x) >> t)))
    #define Ch(x, y, z) ((x & y) ^ (~x & z))
    #define Parity(x, y, z) (x ^ y ^ z)
    #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
    #define Sigma_Maj_0(x) (Rot_Right(2, x) ^ Rot_Right(13, x) ^ Rot_Right(22, x))
    #define Sigma_Maj_1(x) (Rot_Right(6, x) ^ Rot_Right(11, x) ^ Rot_Right(25, x))
    #define Sigma_Min_0(x) (Rot_Right(7, x) ^ Rot_Right(18, x) ^ (x >> 3))
    #define Sigma_Min_1(x) (Rot_Right(17, x) ^ Rot_Right(19, x) ^ (x >> 10))

    const unsigned int K[] =
    {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };

    unsigned int i;
    unsigned int a,b,c,d,e,f,g,h,T1,T2;
    unsigned int W[64];

    Load_32Int_Buffer(p, W);

    for (i = 16; i < 64; i++)
        W[i] = Sigma_Min_1(W[i-2]) + W[i-7] + Sigma_Min_0(W[i-15]) + W[i-16];

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (i = 0; i < 64; i++)
    {
        T1 = h + Sigma_Maj_1(e) + Ch(e, f, g) + K[i] + W[i];
        T2 = Sigma_Maj_0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
}

/*************************************************************************************************************************/

/* The function SHA512_Iterate_Hash implements the SHA512 hash iteration function. 
   See the NIST documentation (FIPS PUB 180-4) for details. */


void SHA512_Iterate_Hash(struct sha_word_pointer *p, uint64_t *H)
{

#define Sigma_512_0(x)  (((x << (64 - 28))|(x >> 28)) ^ ((x << (64 - 34))|(x >> 34)) ^ ((x << (64 - 39))|(x >> 39)))
#define Sigma_512_1(x)  (((x << (64 - 14))|(x >> 14)) ^ ((x << (64 - 18))|(x >> 18)) ^ ((x << (64 - 41))|(x >> 41)))
#define Sigma_512_2(x)  (((x << (64 - 1))|(x >> 1)) ^ ((x << (64 - 8))|(x >> 8)) ^ (x >> 7))
#define Sigma_512_3(x)  (((x << (64 - 19))|(x >> 19)) ^ ((x << (64 - 61))|(x >> 61)) ^ (x >> 6))
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Parity(x, y, z) (x ^ y ^ z)
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

const uint64_t K[80] = {

    0x428A2F98D728AE22,  0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,  0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,  0x59F111F1B605D019,
    0x923F82A4AF194F9B,  0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,  0x12835B0145706FBE,
    0x243185BE4EE4B28C,  0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,  0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,  0xC19BF174CF692694,
    0xE49B69C19EF14AD2,  0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,  0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,  0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,  0x76F988DA831153B5,
    0x983E5152EE66DFAB,  0xA831C66D2DB43210,
    0xB00327C898FB213F,  0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,  0xD5A79147930AA725,
    0x06CA6351E003826F,  0x142929670A0E6E70,
    0x27B70A8546D22FFC,  0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,  0x53380D139D95B3DF,
    0x650A73548BAF63DE,  0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,  0x92722C851482353B,
    0xA2BFE8A14CF10364,  0xA81A664BBC423001,
    0xC24B8B70D0F89791,  0xC76C51A30654BE30,
    0xD192E819D6EF5218,  0xD69906245565A910,
    0xF40E35855771202A,  0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,  0x1E376C085141AB53,
    0x2748774CDF8EEB99,  0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,  0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,  0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,  0x78A5636F43172F60,
    0x84C87814A1F0AB72,  0x8CC702081A6439EC,
    0x90BEFFFA23631E28,  0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,  0xC67178F2E372532B,
    0xCA273ECEEA26619C,  0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,  0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,  0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,  0x1B710B35131C471B,
    0x28DB77F523047D84,  0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,  0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,  0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,  0x6C44198C4A475817 };

    int i;
    uint64_t a, b, c, d, e, f, g, h, T1, T2, W[80];

    Load_64Int_Buffer(p, W);

    for (i = 16; i < 80; i++)
        W[i] = Sigma_512_3(W[i-2]) + W[i-7] + Sigma_512_2(W[i-15]) + W[i-16];
    
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (i = 0; i < 80; i++)
    {
        T1 = h + Sigma_512_1(e) + Ch(e, f, g) + K[i] + W[i];
        T2 = Sigma_512_0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
}
