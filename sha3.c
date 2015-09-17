#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "global.h"
#include "sha3.h"

#define SHA3_PADDING_BITS 4UL
#define SHA3_PADDING_HEAD 0x06UL
#define SHA3_PADDING_TAIL 0x80UL

unsigned char *sha3_sponge(const uint64_t *, unsigned long, unsigned long, unsigned long);
void sha3_permute(uint64_t [STATE_LINE][STATE_LINE], const unsigned long [STATE_LINE][STATE_LINE]);
uint64_t sha3_rotate(uint64_t, unsigned long);

unsigned char *sha3_224(const void *input, unsigned long input_bits) {
	return sha3(input, input_bits, 224UL);
}

unsigned char *sha3_256(const void *input, unsigned long input_bits) {
	return sha3(input, input_bits, 256UL);
}

unsigned char *sha3_384(const void *input, unsigned long input_bits) {
	return sha3(input, input_bits, 384UL);
}

unsigned char *sha3_512(const void *input, unsigned long input_bits) {
	return sha3(input, input_bits, 512UL);
}

unsigned char *sha3(const void *input, unsigned long input_bits, unsigned long hash_bits) {
unsigned char *padded, *hash;
unsigned long state_bits = STATE_SQUARE*WORD_BITS_MAX, rate, padded_bits;

	/* Check hash length and Compute rate value */
	if (hash_bits && 2*hash_bits < state_bits) {
		rate = state_bits-2*hash_bits;
		if (rate%WORD_BITS_MAX) {
			return NULL;
		}
	}
	else {
		return NULL;
	}

	/* Compute length of padding buffer (multiple of rate) */
	padded_bits = padding_length(input_bits, rate, SHA3_PADDING_BITS);

	/* Padding */
	padded = padding(input, input_bits, padded_bits, SHA3_PADDING_HEAD, SHA3_PADDING_TAIL);
	if (!padded) {
		return NULL;
	}

#ifdef SHA3_DEBUG
	sha3_print_hash(input, input_bits, "input ");
	sha3_print_hash(padded, padded_bits, "padded");
#endif

	/* Absorb input and Squeeze hash output at the same rate */
	hash = sha3_sponge((const uint64_t *)padded, padded_bits >> POWER_MAX, rate >> POWER_MAX, hash_bits);

	free(padded);
	return hash;
}

unsigned char *sha3_sponge(const uint64_t *input, unsigned long input_words, unsigned long rate, unsigned long hash_bits) {
unsigned long w, s, r;
const unsigned long rotate[STATE_LINE][STATE_LINE] = {
	{ 0, 36, 3, 41, 18 },
	{ 1, 44, 10, 45, 2 },
	{ 62, 6, 43, 15, 61 },
	{ 28, 55, 25, 21, 56 },
	{ 27, 20, 39, 8, 14 }
};
unsigned long alloc_bytes;
uint64_t state[STATE_LINE][STATE_LINE] = { { 0 } }, *hash;

	/* Absorb input */
	w = 0;
	do {
		for (r = 0; r < rate; w++, r++) {
			state[state_y[r]][state_x[r]] ^= input[w];
		}
		while (r < STATE_SQUARE) {
			state[state_y[r]][state_x[r]] ^= 0;
			r++;
		}
		sha3_permute(state, rotate);
	}
	while (w < input_words);

	/* Squeeze hash output */
	alloc_bytes = modulus_aligned(hash_bits, 8UL) >> 3;
	alloc_bytes = modulus_aligned(alloc_bytes, sizeof(uint64_t));
	hash = calloc(alloc_bytes, 1UL);
	if (hash) {
		w = 0;
		s = 0;
		do {
			for (r = 0; w < hash_bits && r < rate; w += WORD_BITS_MAX, r++) {
				hash[s++] = state[state_y[r]][state_x[r]];
			}
			if (w < hash_bits) {
				sha3_permute(state, rotate);
			}
		}
		while (w < hash_bits);
		hash[s-1] &= truncate[w-hash_bits];
	}

	return (unsigned char *)hash;
}

void sha3_permute(uint64_t a[STATE_LINE][STATE_LINE], const unsigned long r[STATE_LINE][STATE_LINE]) {
unsigned long i, x, y;
uint64_t c[STATE_LINE], d[STATE_LINE], b[STATE_LINE][STATE_LINE];
	for (i = 0; i < CYCLES_MAX; i++) {

		/* THETA */
		for (x = 0; x < STATE_LINE; x++) {
			c[x] = a[x][0];
			for (y = 1; y < STATE_LINE; y++) {
				c[x] ^= a[x][y];
			}
		}
		for (x = 0; x < STATE_LINE; x++) {
			d[x] = c[sub1[x]] ^ sha3_rotate(c[add1[x]], 1UL);
			for (y = 0; y < STATE_LINE; y++) {
				a[x][y] ^= d[x];
			}
		}

		/* RHO/PI */
		for (x = 0; x < STATE_LINE; x++) {
			for (y = 0; y < STATE_LINE; y++) {
				b[y][sum2x3y[x][y]] = sha3_rotate(a[x][y], r[x][y]);
			}
		}

		/* CHI */
		for (x = 0; x < STATE_LINE; x++) {
			for (y = 0; y < STATE_LINE; y++) {
				a[x][y] = b[x][y] ^ ((~b[add1[x]][y]) & b[add2[x]][y]);
			}
		}

		/* IOTA */
		a[0][0] ^= rc[i];
	}
}

uint64_t sha3_rotate(uint64_t value, unsigned long shift) {
	return shift ? (value << shift) | (value >> (WORD_BITS_MAX-shift)):value;
}

void sha3_print_hash(const unsigned char *hash, unsigned long hash_bits, const char *title, ...) {
va_list args;
	va_start(args, title);
	vprintf(title, args);
	va_end(args);
	print_hash(hash, hash_bits);
}
