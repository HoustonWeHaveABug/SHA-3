#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"
#include "global.h"
#include "keccak.h"

#define KECCAK_PADDING_BITS 2UL
#define KECCAK_PADDING_HEAD 0x01UL
#define KECCAK_PADDING_TAIL 0x80UL

struct word_s {
	unsigned long power;
	unsigned long bits;
	unsigned long cycles;
	uint64_t mask;
};
typedef struct word_s word_t;

unsigned char *keccak_sponge(const word_t *, const uint64_t *, unsigned long, unsigned long, unsigned long);
void keccak_absorb(const uint64_t *, unsigned long *, unsigned long *, unsigned long, uint64_t *);
void keccak_squeeze(const uint64_t *, unsigned long, uint64_t *, unsigned long *, unsigned long *);
void keccak_permute(const word_t *, uint64_t [STATE_LINE][STATE_LINE], const unsigned long [STATE_LINE][STATE_LINE]);
uint64_t keccak_rotate(const word_t *, uint64_t, unsigned long);

word_t words[POWER_MAX+1] = {
	{ 0, 1, 12, UINT64_C(0x0000000000000001) },
	{ 1, 2, 14, UINT64_C(0x0000000000000003) },
	{ 2, 4, 16, UINT64_C(0x000000000000000F) },
	{ 3, 8, 18, UINT64_C(0x00000000000000FF) },
	{ 4, 16, 20, UINT64_C(0x000000000000FFFF) },
	{ 5, 32, 22, UINT64_C(0x00000000FFFFFFFF) },
	{ 6, 64, 24, UINT64_C(0xFFFFFFFFFFFFFFFF) }
};

unsigned char *keccak_sha3_224(const void *input, unsigned long input_bits) {
	return keccak(input, input_bits, POWER_MAX, 1152UL, 224UL);
}

unsigned char *keccak_sha3_256(const void *input, unsigned long input_bits) {
	return keccak(input, input_bits, POWER_MAX, 1088UL, 256UL);
}

unsigned char *keccak_sha3_384(const void *input, unsigned long input_bits) {
	return keccak(input, input_bits, POWER_MAX, 832UL, 384UL);
}

unsigned char *keccak_sha3_512(const void *input, unsigned long input_bits) {
	return keccak(input, input_bits, POWER_MAX, 576UL, 512UL);
}

unsigned char *keccak(const void *input, unsigned long input_bits, unsigned long power, unsigned long rate, unsigned long hash_bits) {
unsigned char *padded, *hash;
unsigned long state_bits, padded_bits;

	/* Check power and Compute word length */
	if (power > POWER_MAX) {
		errno = EINVAL;
		perror("keccak/power");
		return NULL;
	}
	state_bits = STATE_SQUARE*words[power].bits;

	/* Check rate and hash length */
	if (hash_bits) {
		if (!rate || rate > state_bits) {
			errno = EINVAL;
			perror("keccak/rate");
			return NULL;
		}
	}
	else {
		errno = EINVAL;
		perror("keccak/hash length");
		return NULL;
	}

	/* Compute length of padding buffer (multiple of rate) */
	padded_bits = padding_length(input_bits, rate, KECCAK_PADDING_BITS);

	/* Padding */
	padded = padding(input, input_bits, padded_bits, KECCAK_PADDING_HEAD, KECCAK_PADDING_TAIL);
	if (!padded) {
		return NULL;
	}

#ifdef SHA3_DEBUG
	keccak_print_hash(input, input_bits, "input ");
	keccak_print_hash(padded, padded_bits, "padded");
#endif

	/* Absorb input and Squeeze hash output at the same rate */
	hash = keccak_sponge(&words[power], (const uint64_t *)padded, padded_bits, rate, hash_bits);

	free(padded);
	return hash;
}

unsigned char *keccak_sponge(const word_t *word, const uint64_t *input, unsigned long input_bits, unsigned long rate, unsigned long hash_bits) {
unsigned long w, b, s, r;
const unsigned long rotate[STATE_LINE][STATE_LINE] = {
	{ 0%word->bits, 36%word->bits, 3%word->bits, 41%word->bits, 18%word->bits },
	{ 1%word->bits, 44%word->bits, 10%word->bits, 45%word->bits, 2%word->bits },
	{ 62%word->bits, 6%word->bits, 43%word->bits, 15%word->bits, 61%word->bits },
	{ 28%word->bits, 55%word->bits, 25%word->bits, 21%word->bits, 56%word->bits },
	{ 27%word->bits, 20%word->bits, 39%word->bits, 8%word->bits, 14%word->bits }
};
unsigned long last_r = rate%word->bits, alloc_bytes, trunc_bits;
uint64_t state[STATE_LINE][STATE_LINE] = { { 0 } }, *hash;

	rate -= last_r;
	rate >>= word->power;

	/* Absorb input */
	w = 0;
	b = 0;
	s = 0;
	do {
		for (r = 0; r < rate; w += word->bits, r++) {
			keccak_absorb(&input[s], &b, &s, word->bits, &state[state_y[r]][state_x[r]]);
		}
		if (last_r) {

			/* Rate not proportional to word length */
			keccak_absorb(&input[s], &b, &s, last_r, &state[state_y[r]][state_x[r]]);
			w += last_r;
			r++;
		}
		while (r < STATE_SQUARE) {
			state[state_y[r]][state_x[r]] ^= 0;
			r++;
		}
		keccak_permute(word, state, rotate);
	}
	while (w < input_bits);

	/* Squeeze hash output */
	alloc_bytes = modulus_aligned(hash_bits, 8UL) >> 3;
	alloc_bytes = modulus_aligned(alloc_bytes, sizeof(uint64_t));
	hash = calloc(alloc_bytes, 1UL);
	if (hash) {
		w = 0;
		b = 0;
		s = 0;
		do {
			for (r = 0; w < hash_bits && r < rate; w += word->bits, r++) {
				keccak_squeeze(&state[state_y[r]][state_x[r]], word->bits, &hash[s], &b, &s);
			}
			if (w < hash_bits && last_r) {

				/* Rate not proportional to word length */
				keccak_squeeze(&state[state_y[r]][state_x[r]], last_r, &hash[s], &b, &s);
				w += last_r;
			}
			if (w < hash_bits) {
				keccak_permute(word, state, rotate);
			}
		}
		while (w < hash_bits);
		trunc_bits = w-hash_bits;
		if (trunc_bits) {
			if (!b) {
				b = WORD_BITS_MAX;
				s--;
			}
			else {
				if (trunc_bits > b) {
					trunc_bits -= b;
					b = WORD_BITS_MAX;
					hash[s--] = 0;
				}
			}
			hash[s] &= truncate[WORD_BITS_MAX-b+trunc_bits];
		}
	}

	return (unsigned char *)hash;
}

void keccak_absorb(const uint64_t *input_sector, unsigned long *b, unsigned long *s, unsigned long word_bits, uint64_t *state_word) {
	*state_word ^= (*input_sector >> *b) & truncate[WORD_BITS_MAX-word_bits];
	*b += word_bits;
	if (*b >= WORD_BITS_MAX) {

		/* Rate not proportional to word length */
		*b -= WORD_BITS_MAX;
		(*s)++;
		if (*b) {
			input_sector++;
			*state_word ^= (*input_sector << (word_bits-*b)) & truncate[WORD_BITS_MAX-word_bits];
		}
	}
}

void keccak_squeeze(const uint64_t *state_word, unsigned long word_bits, uint64_t *hash_sector, unsigned long *b, unsigned long *s) {
	*hash_sector |= *state_word << *b;
	*b += word_bits;
	if (*b >= WORD_BITS_MAX) {

		/* Rate not proportional to word length */
		*b -= WORD_BITS_MAX;
		(*s)++;
		if (*b) {
			hash_sector++;
			*hash_sector |= *state_word >> (word_bits-*b);
		}
	}
}

void keccak_permute(const word_t *word, uint64_t a[STATE_LINE][STATE_LINE], const unsigned long r[STATE_LINE][STATE_LINE]) {
unsigned long i, x, y;
uint64_t c[STATE_LINE], d[STATE_LINE], b[STATE_LINE][STATE_LINE];
	for (i = 0; i < word->cycles; i++) {

		/* THETA */
		for (x = 0; x < STATE_LINE; x++) {
			c[x] = a[x][0];
			for (y = 1; y < STATE_LINE; y++) {
				c[x] ^= a[x][y];
			}
		}
		for (x = 0; x < STATE_LINE; x++) {
			d[x] = c[sub1[x]] ^ keccak_rotate(word, c[add1[x]], 1UL);
			for (y = 0; y < STATE_LINE; y++) {
				a[x][y] ^= d[x];
			}
		}

		/* RHO/PI */
		for (x = 0; x < STATE_LINE; x++) {
			for (y = 0; y < STATE_LINE; y++) {
				b[y][sum2x3y[x][y]] = keccak_rotate(word, a[x][y], r[x][y]);
			}
		}

		/* CHI */
		for (x = 0; x < STATE_LINE; x++) {
			for (y = 0; y < STATE_LINE; y++) {
				a[x][y] = b[x][y] ^ ((~b[add1[x]][y]) & b[add2[x]][y]);
			}
		}

		/* IOTA */
		a[0][0] ^= rc[i] & word->mask;
	}
}

uint64_t keccak_rotate(const word_t *word, uint64_t value, unsigned long shift) {
	return shift ? ((value << shift) | (value >> (word->bits-shift))) & word->mask:value;
}

void keccak_print_hash(const unsigned char *hash, unsigned long hash_bits, const char *title, ...) {
va_list args;
	va_start(args, title);
	vprintf(title, args);
	va_end(args);
	print_hash(hash, hash_bits);
}
