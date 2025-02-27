/***************************************************************************************************************************************
 * FILENAME: shalib.h
 *
 * Copyright (c) 2016 Anders Nordenfelt
 *
 * CONTENT: Declares the sha_word_pointer and the functions defined in shalib.c
 *
 **************************************************************************************************************************************/

#ifndef __SHALIB__
#define __SHALIB__

/* The sha_word_pointer defines a pointer type that acts as a virtual concatenation between the char arrays to be hashed 
   and the pad, or alternatively the file to be hashed and the pad */ 

struct sha_word_pointer
{
    unsigned char buffer[128];                /* space to store a buffer when needed                                        */

    uint64_t tot_byte_size;                   /* the total size in bytes of the text including the pad                      */

    char **strings;                           /* pointer to the array of strings                                            */
    uint64_t array_index;                     /* index specifying in which string the pointer is positioned                 */
    uint64_t array_position;                  /* index specifying where in the current string the pointer is positioned     */
    uint64_t nr_of_strings;                   /* the number of strings in the concatenation                                 */
    uint64_t *strings_byte_size;              /* array containing the byte sizes of the strings in the concatenation        */

    FILE *fp;                                 /* pointer to the file to be hashed, if any
                                              IMPORTANT! this pointer must be set to NULL if you want to hash strings instead*/
    uint64_t file_byte_size;                  /* size in bytes of the file to be hashed                                     */
    uint64_t file_position;                   /* position in the file                                                       */

    unsigned char *pad;                       /* the pad                                                                    */
    unsigned int pad_byte_size;               /* pad length in bytes                                                        */
    unsigned int pad_position;                /* specifies the position in the pad                                          */
    int is_in_pad;                            /* specifies whether the pointer is in the pad or not                         */
};

void Set_Zero(struct sha_word_pointer *p);

void Set_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size, unsigned int BLOCK_SIZE);


void Conv_32Int_To_Word(uint32_t i, char *a);

uint32_t Conv_Word_To_32Int(unsigned char *a);

void Set_64Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size);

void Load_String_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W);

void Load_File_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W);

void Load_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W);


void Conv_64Int_To_Word(uint64_t i, char *a);

uint64_t Conv_Word_To_64Int(unsigned char *a);

void Set_128Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size);

void Load_String_64Int_Buffer(struct sha_word_pointer *p, uint64_t* W);

void Load_File_64Int_Buffer(struct sha_word_pointer *p, uint64_t* W);

void Load_64Int_Buffer(struct sha_word_pointer *p, uint64_t* W);


void SHA1_Iterate_Hash(struct sha_word_pointer *p, uint32_t *H);

void SHA256_Iterate_Hash(struct sha_word_pointer *p, uint32_t *H);

void SHA512_Iterate_Hash(struct sha_word_pointer *p, uint64_t *H);

void HMAC32(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest, void (*SHA)(char *text, uint64_t text_byte_size, uint32_t *hash), void (*SHA_Concat)(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash), unsigned int HASH_SIZE);

void HMAC64(char *key, unsigned int key_size, char *text, uint64_t text_size, uint64_t *digest, void (*SHA)(char *text, uint64_t text_byte_size, uint64_t *hash), void (*SHA_Concat)(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint64_t *hash), unsigned int HASH_SIZE);

#endif
