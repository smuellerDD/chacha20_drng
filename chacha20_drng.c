/*
 * Copyright (C) 2016, Stephan Mueller <smueller@chronox.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2
 * are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

#include "chacha20_drng.h"

#define MAJVERSION 1   /* API / ABI incompatible changes,
			* functional changes that require consumer
			* to be updated (as long as this number is
			* zero, the API is not considered stable
			* and can change without a bump of the
			* major version). */
#define MINVERSION 2   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 1   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

#define CHACHA20_DRNG_ALIGNMENT	8	/* allow u8 to u32 conversions */

/*********************************** Helper ***********************************/

#define min(x, y) ((x < y) ? x : y)

static inline void memset_secure(void *s, int c, uint32_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}

static inline void get_time(time_t *sec, uint32_t *nsec)
{
	struct timespec time;

	if (clock_gettime(CLOCK_REALTIME, &time) == 0) {
		if (sec)
			*sec = time.tv_sec;
		if (nsec)
			*nsec = time.tv_nsec;
	}
}

static inline uint32_t rol32(uint32_t x, int n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}

static inline uint32_t ror32(uint32_t x, int n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

/* Byte swap for 32-bit and 64-bit integers. */
static inline uint32_t _bswap32(uint32_t x)
{
	return ((rol32(x, 8) & 0x00ff00ffL) | (ror32(x, 8) & 0xff00ff00L));
}

/* Endian dependent byte swap operations.  */
#if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define le_bswap32(x) _bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define le_bswap32(x) ((uint32_t)(x))
#else
#error "Endianess not defined"
#endif

/******************************* ChaCha20 Block *******************************/

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_KEY_SIZE_WORDS (CHACHA20_KEY_SIZE / sizeof(uint32_t))

/* State according to RFC 7539 section 2.3 */
struct chacha20_state {
	uint32_t constants[4];
	union {
		uint32_t u[CHACHA20_KEY_SIZE_WORDS];
		uint8_t  b[CHACHA20_KEY_SIZE];
	} key;
	uint32_t counter;
	uint32_t nonce[3];
};

#define CHACHA20_BLOCK_SIZE sizeof(struct chacha20_state)
#define CHACHA20_BLOCK_SIZE_WORDS (CHACHA20_BLOCK_SIZE / sizeof(uint32_t))

/* ChaCha20 block function according to RFC 7539 section 2.3 */
static void chacha20_block(uint32_t *state, void *stream)
{
	uint32_t i, ws[CHACHA20_BLOCK_SIZE_WORDS], *out = stream;

	for (i = 0; i < CHACHA20_BLOCK_SIZE_WORDS; i++)
		ws[i] = state[i];

	for (i = 0; i < 10; i++) {
		/* Quarterround 1 */
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],  16);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],  12);
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],   8);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],   7);

		/* Quarterround 2 */
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],  16);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],  12);
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],   8);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],   7);

		/* Quarterround 3 */
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],  16);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10], 12);
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],   8);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10],  7);

		/* Quarterround 4 */
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],  16);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11], 12);
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],   8);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11],  7);

		/* Quarterround 5 */
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],  16);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10], 12);
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],   8);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10],  7);

		/* Quarterround 6 */
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],  16);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11], 12);
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],   8);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11],  7);

		/* Quarterround 7 */
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],  16);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],  12);
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],   8);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],   7);

		/* Quarterround 8 */
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],  16);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],  12);
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],   8);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],   7);
	}

	for (i = 0; i < CHACHA20_BLOCK_SIZE_WORDS; i++)
		out[i] = le_bswap32(ws[i] + state[i]);

	state[12]++;
}

static inline int drng_chacha20_selftest_one(struct chacha20_state *state,
					     uint32_t *expected)
{
	uint32_t result[CHACHA20_BLOCK_SIZE_WORDS];

	chacha20_block(&state->constants[0], result);
	return memcmp(expected, result, CHACHA20_BLOCK_SIZE);
}

static int drng_chacha20_selftest(void)
{
	struct chacha20_state chacha20;
	uint32_t expected[CHACHA20_BLOCK_SIZE_WORDS];

	/* Test vector according to RFC 7539 section 2.3.2 */
	chacha20.constants[0] = 0x61707865; chacha20.constants[1] = 0x3320646e;
	chacha20.constants[2] = 0x79622d32; chacha20.constants[3] = 0x6b206574;
	chacha20.key.u[0]     = 0x03020100; chacha20.key.u[1]     = 0x07060504;
	chacha20.key.u[2]     = 0x0b0a0908; chacha20.key.u[3]     = 0x0f0e0d0c;
	chacha20.key.u[4]     = 0x13121110; chacha20.key.u[5]     = 0x17161514;
	chacha20.key.u[6]     = 0x1b1a1918; chacha20.key.u[7]     = 0x1f1e1d1c;
	chacha20.counter      = 0x00000001; chacha20.nonce[0]     = 0x09000000;
	chacha20.nonce[1]     = 0x4a000000; chacha20.nonce[2]     = 0x00000000;

	expected[0] = 0xe4e7f110;  expected[1] = 0x15593bd1;
	expected[2] = 0x1fdd0f50;  expected[3] = 0xc47120a3;
	expected[4] = 0xc7f4d1c7;  expected[5] = 0x0368c033;
	expected[6] = 0x9aaa2204;  expected[7] = 0x4e6cd4c3;
	expected[8] = 0x466482d2;  expected[9] = 0x09aa9f07;
	expected[10] = 0x05d7c214; expected[11] = 0xa2028bd9;
	expected[12] = 0xd19c12b5; expected[13] = 0xb94e16de;
	expected[14] = 0xe883d0cb; expected[15] = 0x4e3c50a2;

	return drng_chacha20_selftest_one(&chacha20, &expected[0]);
}

/******************************** Seed Source ********************************/

#ifdef GETRANDOM	/* getrandom system call */

#include <limits.h>

struct seed_source {
#define OVERSAMPLINGRATE 1
	void *unused;
};

static int drng_seedsource_alloc(struct seed_source *source)
{
	(void)source;
	return 0;
}

static void drng_seedsource_dealloc(struct seed_source *source)
{
	(void)source;
	return;
}

static int drng_get_seed(struct seed_source *source, uint8_t *buf,
			 uint32_t buflen)
{
	uint32_t len = 0;
	ssize_t ret;

	(void)source;

	if (buflen > INT_MAX)
		return 0;

	do {
		ret = syscall(__NR_getrandom, (buf + len), (buflen - len), 0);
		if (0 < ret)
			len += ret;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > len);

	return len;
}

#elif JENT		/* CPU execution time jitter RNG */
#include "jitterentropy.h"

struct seed_source {
#define OVERSAMPLINGRATE 2
	struct rand_data *ec;
};

static int drng_seedsource_alloc(struct seed_source *source)
{
	int ret = jent_entropy_init();

	if (ret) {
		printf("The initialization failed with error code %d\n", ret);
		return ret;
	}

	source->ec = jent_entropy_collector_alloc(0, 0);
	if (!source->ec)
		return 1;

	return 0;
}

static void drng_seedsource_dealloc(struct seed_source *source)
{
	jent_entropy_collector_free(source->ec);
	source->ec = NULL;
}

static int drng_get_seed(struct seed_source *source, uint8_t *buf,
			 uint32_t buflen)
{
	return jent_read_entropy(source->ec, (char *)buf, buflen);
}

#elif DEVRANDOM		/* Reading of /dev/random */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

struct seed_source {
#define OVERSAMPLINGRATE 1
	int fd;
};

static int drng_get_seed(struct seed_source *source, uint8_t *buf,
			 uint32_t buflen)
{
	uint32_t len = 0;
	ssize_t ret;

	if (buflen > INT_MAX)
		return 0;

	do {
		ret = read(source->fd, (buf + len), (buflen - len));
		if (0 < ret)
			len += ret;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > len);

	return len;
}

static int drng_seedsource_alloc(struct seed_source *source)
{
	source->fd = open("/dev/random", O_RDONLY|O_CLOEXEC);
	if (0 > source->fd)
		return 1;

	return 0;
}

static void drng_seedsource_dealloc(struct seed_source *source)
{
	close(source->fd);
	source->fd = -1;
}

#else
#error "No seed source defined"
#endif

/******************************* ChaCha20 DRNG *******************************/

struct chacha20_drng {
	struct chacha20_state chacha20;
	struct seed_source source;
	time_t last_seeded;
	uint64_t generated_bytes;
};

/**
 * Update of the ChaCha20 state by generating one ChaCha20 block which is
 * equal to the state of the ChaCha20. The generated block is XORed into
 * the key part of the state. This shall ensure backtracking resistance as well
 * as a proper mix of the ChaCha20 state once the key is injected.
 */
static inline void drng_chacha20_update(struct chacha20_state *chacha20)
{
	uint32_t i, tmp[CHACHA20_BLOCK_SIZE_WORDS];

	chacha20_block(&chacha20->constants[0], tmp);
	for (i = 0; i < CHACHA20_KEY_SIZE_WORDS; i++) {
		chacha20->key.u[i] ^= tmp[i];
		chacha20->key.u[i] ^= tmp[i + CHACHA20_KEY_SIZE_WORDS];
	}
	memset_secure(tmp, 0, sizeof(tmp));

	/* Deterministic increment of nonce as required in RFC 7539 chapter 4 */
	chacha20->nonce[0]++;
	if (chacha20->nonce[0] == 0)
		chacha20->nonce[1]++;
	if (chacha20->nonce[1] == 0)
		chacha20->nonce[2]++;

	/* Leave counter untouched as it is start value is undefined in RFC */
}

/**
 * Seed the ChaCha20 DRNG by injecting the input data into the key part of
 * the ChaCha20 state. If the input data is longer than the ChaCha20 key size,
 * perform a ChaCha20 operation after processing of key size input data.
 * This operation shall spread out the entropy into the ChaCha20 state before
 * new entropy is injected into the key part.
 *
 * The approach taken here is logically similar to a CBC-MAC: The input data
 * is processed chunk-wise. Each chunk is encrypted, the output is XORed with
 * the next chunk of the input and then encrypted again. I.e. the
 * ChaCha20 CBC-MAC of the seed data is injected into the DRNG state.
 */
static int drng_chacha20_seed(struct chacha20_state *chacha20,
			      const uint8_t *inbuf, uint32_t inbuflen)
{
	while (inbuflen) {
		uint32_t i, todo = min(inbuflen, CHACHA20_KEY_SIZE);

		for (i = 0; i < todo; i++)
			chacha20->key.b[i] ^= inbuf[i];

		/* Break potential dependencies between the inbuf key blocks */
		drng_chacha20_update(chacha20);
		inbuf += todo;
		inbuflen -= todo;
	}

	return 0;
}

/**
 * Chacha20 DRNG generation of random numbers: the stream output of ChaCha20
 * is the random number. After the completion of the generation of the
 * stream, the entire ChaCha20 state is updated.
 *
 * Note, as the ChaCha20 implements a 32 bit counter, we must ensure
 * that this function is only invoked for at most 2^32 - 1 ChaCha20 blocks
 * before a reseed or an update happens. This is ensured by the variable
 * outbuflen which is a 32 bit integer defining the number of bytes to be
 * generated by the ChaCha20 DRNG. At the end of this function, an update
 * operation is invoked which implies that the 32 bit counter will never be
 * overflown in this implementation.
 */
static int drng_chacha20_generate(struct chacha20_state *chacha20,
				  uint8_t *outbuf, uint32_t outbuflen)
{
	while (outbuflen >= CHACHA20_BLOCK_SIZE) {
		chacha20_block(&chacha20->constants[0], outbuf);
		outbuf += CHACHA20_BLOCK_SIZE;
		outbuflen -= CHACHA20_BLOCK_SIZE;
	}

	if (outbuflen) {
		uint8_t stream[CHACHA20_BLOCK_SIZE];

		chacha20_block(&chacha20->constants[0], stream);
		memcpy(outbuf, stream, outbuflen);
		memset_secure(stream, 0, sizeof(stream));
	}

	drng_chacha20_update(chacha20);

	return 0;
}

/**
 * Allocation of the DRBG state
 */
static int drng_chacha20_alloc(struct chacha20_drng **out)
{
	struct chacha20_drng *drng;
	uint32_t i, v = 0;
	int ret;

	if (drng_chacha20_selftest()) {
		printf("Selftest failed\n");
		return -EFAULT;
	}

	ret = posix_memalign((void *)&drng, CHACHA20_DRNG_ALIGNMENT,
			     sizeof(*drng));
	if (ret) {
		printf("Could not allocate buffer for ChaCha20 state: %d\n",
		       ret);
		return -ret;
	}

	/* prevent paging out of the memory state to swap space */
	mlock(drng, sizeof(*drng));

	memset(drng, 0, sizeof(*drng));

	memcpy(&drng->chacha20.constants[0], "expand 32-byte k", 16);

	for (i = 0; i < CHACHA20_KEY_SIZE_WORDS; i++) {
		get_time(NULL, &v);
		drng->chacha20.key.u[i] ^= v;
	}

	for (i = 0; i < 3; i++) {
		get_time(NULL, &v);
		drng->chacha20.nonce[i] ^= v;
	}

	*out = drng;

	return 0;
}

static void drng_chacha20_dealloc(struct chacha20_drng *drng)
{
	memset_secure(drng, 0, sizeof(*drng));
	free(drng);
}

/***************************** ChaCha20 DRNG API *****************************/

int drng_chacha20_reseed(struct chacha20_drng *drng, const uint8_t *inbuf,
			 uint32_t inbuflen)
{
	uint8_t seed[CHACHA20_KEY_SIZE * OVERSAMPLINGRATE];
	int ret;

	ret = drng_get_seed(&drng->source, seed, sizeof(seed));
	if (ret != sizeof(seed)) {
		printf("Unexpected return code from seed source: %d\n", ret);
		return ret;
	}

	ret = drng_chacha20_seed(&drng->chacha20, seed, sizeof(seed));
	memset_secure(seed, 0, sizeof(seed));
	if (ret)
		return ret;

	if (inbuf && inbuflen)
		ret = drng_chacha20_seed(&drng->chacha20, inbuf, inbuflen);

	get_time(&drng->last_seeded, NULL);
	drng->generated_bytes = 0;

	return ret;
}

int drng_chacha20_init(struct chacha20_drng **drng)
{
	int ret = drng_chacha20_alloc(drng);

	if (ret)
		return ret;

	ret = drng_seedsource_alloc(&(*drng)->source);
	if (ret)
		goto deallocdrng;

	ret = drng_chacha20_reseed(*drng, NULL, 0);
	if (ret)
		goto deallocsource;

	return 0;

deallocsource:
	drng_seedsource_dealloc(&(*drng)->source);
deallocdrng:
	drng_chacha20_dealloc(*drng);

	return ret;
}

void drng_chacha20_destroy(struct chacha20_drng *drng)
{
	drng_seedsource_dealloc(&drng->source);
	drng_chacha20_dealloc(drng);
}

int drng_chacha20_get(struct chacha20_drng *drng, uint8_t *outbuf,
		      uint32_t outbuflen)
{
	time_t now;
	uint32_t nsec;
	int ret;

	get_time(&now, &nsec);

	/*
	 * Reseed if:
	 *	* last seeding was more than 600 seconds ago
	 *	* more than 1<<30 bytes were generated since last reseed
	 */
	if (((now - drng->last_seeded) > 600) ||
	    (drng->generated_bytes > (1<<30))) {
		ret = drng_chacha20_reseed(drng, (uint8_t *)&nsec,
					   sizeof(nsec));

		if (ret)
			return ret;
		drng->last_seeded = now;
		drng->generated_bytes = 0;
	} else {
		ret = drng_chacha20_seed(&drng->chacha20, (uint8_t *)&nsec,
					 sizeof(nsec));
		if (ret)
			return ret;
	}

	ret = drng_chacha20_generate(&drng->chacha20, outbuf, outbuflen);
	if (ret)
		return ret;

	drng->generated_bytes += outbuflen;

	return 0;
}

int drng_chacha20_versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ChaCha20 DRNG %d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
}

uint32_t drng_chacha20_version(void)
{
	uint32_t version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
}
