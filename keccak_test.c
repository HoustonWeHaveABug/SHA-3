#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keccak.h"

int keccak_sha3_test(const unsigned char *, unsigned long, int);

int main(void) {
unsigned char input0bits[1] = { 0x00 }, input5bits[1] = { 0x13 }, input30bits[4] = { 0x53, 0x58, 0x7b, 0x19 }, input1600bits[200], input1605bits[201], input1630bits[204], input144bytes[144] = { 0x00 }, input29bits[4] = { 0x61, 0x62, 0x63, 0x06 }, *hash;
unsigned long rounds, i, min, max, j, k;
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
		if (keccak_sha3_test(input0bits, 0UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (keccak_sha3_test(input5bits, 5UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (keccak_sha3_test(input30bits, 30UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (keccak_sha3_test(input1600bits, 1600UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (keccak_sha3_test(input1605bits, 1605UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		if (keccak_sha3_test(input1630bits, 1630UL, print) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}

		/* Test particular padding cases */
		hash = keccak_sha3_224(input144bytes, 1148UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 224UL, "keccak_sha3_224(input144bytes, 1148) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = keccak_sha3_224(input144bytes, 1149UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 224UL, "keccak_sha3_224(input144bytes, 1149) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}

		/* Test all possible hash lengths using SHA-3 rate */
		for (j = 1; j < 13; j++) {
			hash = keccak(input29bits, 29UL, 0UL, 25-2*j, j);
			if (hash) {
				if (print) {
					keccak_print_hash(hash, j, "keccak(input29bits, 29, 0, %lu, %lu) =", 25-2*j, j);
				}
				free(hash);
			}
			else {
				return EXIT_FAILURE;
			}
		}
		for (min = 1, max = 25, j = 1; j < 7; min <<= 1, max <<= 1, j++) {
			for (k = min; k < max; k += min) {
				hash = keccak(input29bits, 29UL, j, 2*(max-k), k);
				if (hash) {
					if (print) {
						keccak_print_hash(hash, k, "keccak(input29bits, 29, %lu, %lu, %lu) =", j, 2*(max-k), k);
					}
					free(hash);
				}
				else {
					return EXIT_FAILURE;
				}
			}
		}

		/* Additional tests */
		hash = keccak(input29bits, 29UL, 6UL, 1152UL, 223UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 223UL, "keccak(input29bits, 29, 6, 1152, 223) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = keccak(input29bits, 29UL, 6UL, 1100UL, 224UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 224UL, "keccak(input29bits, 29, 6, 1100, 224) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = keccak(input29bits, 29UL, 3UL, 200UL, 128UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 128UL, "keccak(input29bits, 29, 3, 200, 128) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = keccak(input29bits, 29UL, 3UL, 200UL, 224UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 224UL, "keccak(input29bits, 29, 3, 200, 224) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
		hash = keccak(input29bits, 29UL, 2UL, 50UL, 24UL);
		if (hash) {
			if (print) {
				keccak_print_hash(hash, 24UL, "keccak(input29bits, 29, 2, 50, 24) =");
			}
			free(hash);
		}
		else {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int keccak_sha3_test(const unsigned char *input, unsigned long input_bits, int print) {
unsigned char *hash;
	hash = keccak_sha3_224(input, input_bits);
	if (hash) {
		if (print) {
			keccak_print_hash(hash, 224UL, "keccak_sha3_224(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = keccak_sha3_256(input, input_bits);
	if (hash) {
		if (print) {
			keccak_print_hash(hash, 256UL, "keccak_sha3_256(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = keccak_sha3_384(input, input_bits);
	if (hash) {
		if (print) {
			keccak_print_hash(hash, 384UL, "keccak_sha3_384(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	hash = keccak_sha3_512(input, input_bits);
	if (hash) {
		if (print) {
			keccak_print_hash(hash, 512UL, "keccak_sha3_512(input, %lu) =", input_bits);
		}
		free(hash);
	}
	else {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
