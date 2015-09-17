#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"

int sha3_test(const unsigned char *, unsigned long, int);

int main(void) {
unsigned char input0bits[1] = { 0x00 }, input5bits[1] = { 0x13 }, input30bits[4] = { 0x53, 0x58, 0x7b, 0x19 }, input1600bits[200], input1605bits[201], input1630bits[204], input144bytes[144] = { 0x00 }, input29bits[4] = { 0x61, 0x62, 0x63, 0x06 }, *hash;
unsigned long rounds, i, j;
int print;
	scanf("%lu%d", &rounds, &print);
	for (i = 0; i < 200; i++) {
		input1600bits[i] = 0xa3;
		input1605bits[i] = 0xa3;
		input1630bits[i] = 0xa3;
	}
	input1605bits[i] = 0x03;
	while (i < 203) {
		input1630bits[i++] = 0xa3;
	}
	input1630bits[i] = 0x23;

	for (i = 0; i < rounds; i++) {

		/* Test standard hash lengths as per http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing */
		if (sha3_test(input0bits, 0UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (sha3_test(input5bits, 5UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (sha3_test(input30bits, 30UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (sha3_test(input1600bits, 1600UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (sha3_test(input1605bits, 1605UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (sha3_test(input1630bits, 1630UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}

		/* Test particular padding cases */
		hash = sha3_224(input144bytes, 1148UL);
		if (hash) {
			if (print) {
				sha3_print_hash(hash, 224UL, "sha3_224(input144bytes, 1148) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = sha3_224(input144bytes, 1149UL);
		if (hash) {
			if (print) {
				sha3_print_hash(hash, 224UL, "sha3_224(input144bytes, 1149) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}

		/* Test all possible hash lengths */
		for (j = 32; j < 800; j += 32) {
			hash = sha3(input29bits, 29UL, j);
			if (hash) {
				if (print) {
					sha3_print_hash(hash, j, "sha3(input29bits, 29, %lu) =", j);
				}
				free(hash);
			}
			else {
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

int sha3_test(const unsigned char *input, unsigned long input_bits, int print) {
unsigned char *hash;
	hash = sha3_224(input, input_bits);
	if (hash) {
		if (print) {
			sha3_print_hash(hash, 224UL, "sha3_224(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = sha3_256(input, input_bits);
	if (hash) {
		if (print) {
			sha3_print_hash(hash, 256UL, "sha3_256(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = sha3_384(input, input_bits);
	if (hash) {
		if (print) {
			sha3_print_hash(hash, 384UL, "sha3_384(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = sha3_512(input, input_bits);
	if (hash) {
		if (print) {
			sha3_print_hash(hash, 512UL, "sha3_512(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
