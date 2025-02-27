#include "qrcodegen.h" //lekko modified bo coś maskowanie się spierdalało
#include "sha1.h" 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h> 

#define JAVA_INT_MAX 0x7FFFFFFF //decompiled java moment
#define TIME_STEP 30 //co ile sekund ma odświeżać cyferki w totp
#define DIGITS 6 //długość totp.
bool debug = false; //logi (tylko dlatego bo jebaliśmy sie z tym pół dnia by przeportować na ESP8266)

//jakaś tam funkcja zdekompilowana z java'y :p  
uint32_t ctotp(const uint8_t *arr, size_t index) {
    uint32_t result = 0;
    for (size_t i = index; i < index + 4; i++) {
        result = (result << 8) | arr[i];
    }
    return result;
}

//bity robią brrrrrrrrrrr
uint32_t to_big_endian(uint32_t value) {
    return ((value >> 24) & 0xFF) | 
           ((value >> 8) & 0xFF00) | 
           ((value << 8) & 0xFF0000) | 
           ((value << 24) & 0xFF000000);
	
}

//tu sie dzieje cała magia.
int compute_totp(const char *secretHex) {
    size_t secretLen = strlen(secretHex) / 2;
	
    unsigned char *secret = calloc(secretLen, sizeof(unsigned char));
    if (!secret) return -1;

    for (size_t i = 0; i < secretLen; i++) {
        sscanf(secretHex + 2 * i, "%2hhx", &secret[i]);
    }

    uint64_t ts = time(NULL) / TIME_STEP; //czas utc. zapamiętać
	
    uint32_t ts_be = to_big_endian(ts); //convert timestamp na big-endian
	if (debug) {
		printf("TIMESTAMP (GMT+0): %lld \n", ts);
		printf("TIMESTAMP (DIVIDED BY 30): %d \n", ts_be);
		printf("SECRET'S LENGTH: %lld \n", secretLen);
	}
    unsigned char msg[8] = {0};
    memcpy(msg + 4, &ts_be, sizeof(ts_be)); //wjeb do array'a "msg" timestampa -> expected result: 00 00 00 00 {cztery bajty here}
	if (debug) {
		printf("MSG: ");
		for (size_t i = 0; i < sizeof(msg); i++) {
			printf("%02X ", msg[i]);
		}
		printf("\n");
	}
	

    uint32_t outputBytes[5];

    HMAC_SHA1((char*)secret, secretLen, (char*)msg, sizeof(msg), outputBytes); //weź secret'a i msg i przemiel to HMAC'iem SHA1
	if (debug) {
		printf("HMAC: ");
		for (int i = 0; i < 5; i++) {
			printf("%02X ", outputBytes[i]);
		} 
		printf("\n");
	}

    uint8_t outputBytesAsBytes[20]; // jebnij z bitów na bajty.

    for (int i = 0; i < 5; i++) {
        uint32_t val = to_big_endian(outputBytes[i]);  
        memcpy(&outputBytesAsBytes[i * 4], &val, sizeof(val));
    }

    int offset = outputBytesAsBytes[19] & 0xF; //jakaś matma idk
	if (debug) {
		printf("OFFSET: %d \n", offset);
	}
    int magicNumber = (ctotp(outputBytesAsBytes, offset) & JAVA_INT_MAX) % (int)pow(10, DIGITS); //finalnie oblicz TOTP tą dziwną funkcją z zdekompilowanej java'y
	// if (debug) {
		// printf("TOTP: %06d \n", magicNumber);
	// }
	printf("TOTP: %06d \n", magicNumber);
    free(secret);
    return magicNumber;
}

//wyświetl qr'a, jako utf-8 bo najłatwiej w terminalach.
void printQr(const uint8_t qrcode[]) {
    int size = qrcodegen_getSize(qrcode);
    int border = 4;
    
    for (int y = -border; y < size + border; y++) {
        for (int x = -border; x < size + border; x++) {
            printf(qrcodegen_getModule(qrcode, x, y) ? "  " : "██");
        }
        printf("\n");
    }
}

//zrób qr'a.
bool make_qr(int totp, const char* usajd) {
    char text[256];
    snprintf(text, sizeof(text), "https://srln.pl/view/dashboard?ploy=%s&loyal=%06d", usajd, totp);
	if (debug) {
		printf("URL: %s\n", text);
	}

    uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
    uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];
    // dla najbardziej accurate kodu, maskowanie wyłączone. error correction na maxa. rozmiar wtedy powinien być równy 45x45
    bool ok = qrcodegen_encodeText(text, tempBuffer, qrcode, qrcodegen_Ecc_HIGH,
                                   qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                   qrcodegen_Mask_0, true);
    if (ok) printQr(qrcode);
    return ok;
}


int main(void) {
    const char *secrettotpglobal = "secret_here"; //secret wyciągniety z konta żappka.
    const char* usajd = "user_id_here"; //userid wyciągnięte z konta żappka.

    while (1) { 
		system("cls"); //clear terminal
        int totp = compute_totp(secrettotpglobal);
        if (totp < 0) {
            fprintf(stderr, "wyjebało totp :p.\n");
            return EXIT_FAILURE;
        }

        if (!make_qr(totp, usajd)) {
            fprintf(stderr, "wyjebało qr'a :p.\n");
            return EXIT_FAILURE;
        }

        sleep(2); 
    }

    return EXIT_SUCCESS;
}
