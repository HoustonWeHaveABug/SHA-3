#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"

unsigned long padding_length(unsigned long input_bits, unsigned long rate, unsigned long padding_bits) {
unsigned long length;
	length = input_bits ? modulus_aligned(input_bits, rate):rate;
	if (length-input_bits < padding_bits) {
		do {
			length += rate;
		}
		while (length-input_bits < padding_bits);
	}
	return length;
}

unsigned char *padding(const unsigned char *input, unsigned long input_bits, unsigned long padded_bits, unsigned long padding_head, unsigned long padding_tail) {
unsigned char *padded, byte;
unsigned long padded_bytes = modulus_aligned(padded_bits, 8UL) >> 3, alloc_bytes = modulus_aligned(padded_bytes, sizeof(uint64_t)), input_bytes, last_bits;
	padded = calloc(alloc_bytes, 1UL);
	if (!padded) {
		perror("padding");
		return NULL;
	}
	input_bytes = modulus_aligned(input_bits, 8UL) >> 3;
	memcpy(padded, input, input_bytes);
	if (input_bits < padded_bits) {
		last_bits = input_bits%8;
		if (last_bits) {
			padded[input_bytes-1] |= (unsigned char)(padding_head << last_bits);
			byte = (unsigned char)(padding_head >> (8-last_bits));
			if (byte) {
				padded[input_bytes++] = byte;
			}
		}
		else {
			padded[input_bytes++] = (unsigned char)padding_head;
		}
		while (input_bytes < padded_bytes) {
			padded[input_bytes++] = 0;
		}
		last_bits = padded_bits%8;
		if (last_bits) {
			padded[padded_bytes-1] |= (unsigned char)(padding_tail >> (8-last_bits));
			byte = (unsigned char)(padding_tail << last_bits);
			if (byte) {
				padded[padded_bytes-2] |= byte;
			}
		}
		else {
			padded[padded_bytes-1] |= (unsigned char)padding_tail;
		}
	}
	return padded;
}

void print_hash(const unsigned char *hash, unsigned long hash_bits) {
unsigned long hash_bytes = modulus_aligned(hash_bits, 8UL) >> 3, i;
	printf(" 0x");
	for (i = 0; i < hash_bytes; i++) {
		printf("%02x", hash[i]);
	}
	puts("");
}

unsigned long modulus_aligned(unsigned long value, unsigned long modulus) {
unsigned long last = value%modulus;
	if (last) {
		value += modulus-last;
	}
	return value;
}
