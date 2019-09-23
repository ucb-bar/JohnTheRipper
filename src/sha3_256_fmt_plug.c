/* SHA3-256 cracker patch for JtR.
 * Modified from sha3_512_fmt_plug.c by Dhiru Kholia.
 *
 * Thanks to https://github.com/codedot/keccak (Jim McDevitt) for the
 * "delimited suffix" stuff.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA3_256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA3_256);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "KeccakHash.h"

#define FORMAT_LABEL			"Raw-SHA3-256"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE			32
#define SALT_SIZE			0

#define BINARY_ALIGN			4
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		512

#ifndef OMP_SCALE
#define OMP_SCALE			32 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", ""},
	{"6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177", "abcd"},
	{"e77373012411fc8f1ddc0124edc3a4fbb1aac8724ab9811c45a1c86a41133484", "MuchB4tter PassWord !her@"},
	{NULL}
};

static int (*saved_len);
// the Keccak function can read up to next even 8 byte offset.
// making the buffer larger avoid reading past end of buffer
static char (*saved_key)[(((PLAINTEXT_LENGTH+1)+7)/8)*8];
static uint32_t (*crypt_out)
    [(BINARY_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$keccak$", 8))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[8 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$keccak$", 8))
		ciphertext += 8;

	memcpy(out, "$keccak$", 8);
	memcpylwr(out + 8, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		Keccak_HashInstance hash;
		Keccak_HashInitialize(&hash, 1088, 512, 256, 0x06);
		Keccak_HashUpdate(&hash, (unsigned char*)saved_key[index], saved_len[index] * 8);
		Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawSHA3_256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA3 256 " ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
                BINARY_ALIGN,
		SALT_SIZE,
                SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_OMP | FMT_OMP_BAD | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
