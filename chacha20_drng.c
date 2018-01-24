/*
 * Copyright (C) 2016 - 2017, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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
#define MINVERSION 3   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 1   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

#define CHACHA20_DRNG_ALIGNMENT	8	/* allow u8 to u32 conversions */

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

/*********************************** Helper ***********************************/

#define min(x, y) ((x < y) ? x : y)
#define __aligned(x) __attribute__((aligned(x)))

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
static void chacha20_block(uint32_t *state, uint32_t *stream)
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

/********************* getrandom system call seed source *********************/
#ifdef GETRANDOM

#include <limits.h>
static int drng_getrandom_get(uint8_t *buf, uint32_t buflen)
{
	uint32_t len = 0;
	ssize_t ret;

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

#else
static int drng_getrandom_get(uint8_t *buf, uint32_t buflen)
{
	(void)buf;
	(void)buflen;

	return 0;
}

#endif

/*************************** Jitter RNG seed source ***************************/
#ifdef JENT

#include "jitterentropy.h"

struct jent_noise_source {
	struct rand_data *ec;
	int initialized;
};

static struct jent_noise_source jent_noise_source = {
	NULL,
	0,
};

static int drng_jent_alloc()
{
	int ret = jent_entropy_init();

	if (ret) {
		jent_noise_source.initialized = -1;
		return -EFAULT;
	}

	jent_noise_source.ec = jent_entropy_collector_alloc(0, 0);
	if (!jent_noise_source.ec)
		return -ENOMEM;

	return 0;
}

static void drng_jent_dealloc(void)
{
	if (jent_noise_source.initialized != 1)
		return;

	jent_entropy_collector_free(jent_noise_source.ec);
	jent_noise_source.ec = NULL;
	jent_noise_source.initialized = 0;
}

static int drng_jent_get(uint8_t *buf, uint32_t buflen)
{
	if (!jent_noise_source.initialized) {
		int ret = drng_jent_alloc();

		if (ret)
			return ret;

		jent_noise_source.initialized = 1;
	}

	if (jent_noise_source.initialized > 0)
		return jent_read_entropy(jent_noise_source.ec,
					 (char *)buf, buflen);

	return 0;
}

#else
static int drng_jent_get(uint8_t *buf, uint32_t buflen)
{
	(void)buf;
	(void)buflen;

	return 0;
}

static void drng_jent_dealloc(void)
{
	return;
}
#endif

/************************** /dev/random seed source **************************/
#ifdef DEVRANDOM

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

static int random_fd = -1;

static int drng_random_alloc(void)
{
	random_fd = open("/dev/random", O_RDONLY|O_CLOEXEC);
	if (0 > random_fd)
		return -EBADFD;

	return 0;
}

static int drng_random_get(uint8_t *buf, uint32_t buflen)
{
	uint32_t len = 0;
	ssize_t ret;

	if (random_fd == -1) {
		int ret = drng_random_alloc();

		if (ret)
			return ret;
	}

	if (buflen > INT_MAX)
		return 0;

	do {
		ret = read(random_fd, (buf + len), (buflen - len));
		if (0 < ret)
			len += ret;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > len);

	return len;
}

static void drng_random_dealloc(void)
{
	if (random_fd < 0)
		return;

	close(random_fd);
	random_fd = -1;
}

#else
static int drng_random_get(uint8_t *buf, uint32_t buflen)
{
	(void)buf;
	(void)buflen;

	return 0;
}

static void drng_random_dealloc(void)
{
	return;
}
#endif

/******************************* ChaCha20 DRNG *******************************/

struct chacha20_drng {
	struct chacha20_state chacha20;
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
	uint32_t aligned_buf[(CHACHA20_BLOCK_SIZE / sizeof(uint32_t))];

	while (outbuflen >= CHACHA20_BLOCK_SIZE) {
		if ((unsigned long)outbuf & (sizeof(aligned_buf[0]) - 1)) {
			chacha20_block(&chacha20->constants[0], aligned_buf);
			memcpy(outbuf, aligned_buf, CHACHA20_BLOCK_SIZE);
		} else {
			chacha20_block(&chacha20->constants[0],
				       (uint32_t *)outbuf);
		}

		outbuf += CHACHA20_BLOCK_SIZE;
		outbuflen -= CHACHA20_BLOCK_SIZE;
	}

	if (outbuflen) {
		chacha20_block(&chacha20->constants[0], aligned_buf);
		memcpy(outbuf, aligned_buf, outbuflen);
		memset_secure(aligned_buf, 0, sizeof(aligned_buf));
	} else if ((unsigned long)outbuf & (sizeof(aligned_buf[0]) - 1)) {
		memset_secure(aligned_buf, 0, sizeof(aligned_buf));
	}

	drng_chacha20_update(chacha20);

	return 0;
}

static int drng_chacha20_rng_selftest(struct chacha20_drng *drng)
{
	int ret;
	uint8_t outbuf[CHACHA20_KEY_SIZE * 2] __aligned(sizeof(uint32_t));
	uint8_t seed[CHACHA20_KEY_SIZE * 2] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	};

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * and pulling one ChaCha20 DRNG block.
	 */
	uint8_t expected_block[CHACHA20_KEY_SIZE] = {
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
		0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
		0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
		0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7 };

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	 *	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	 *	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	 *	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
	 * and pulling two ChaCha20 DRNG blocks.
	 */
	uint8_t expected_twoblocks[CHACHA20_KEY_SIZE * 2] = {
		0x80, 0xd5, 0xb1, 0x4d, 0x70, 0x5d, 0x3c, 0xa2,
		0x23, 0x43, 0xc2, 0xe2, 0x1a, 0x4b, 0xb7, 0x29,
		0x88, 0xed, 0x02, 0x4b, 0x4f, 0xa5, 0x52, 0xa9,
		0xba, 0x92, 0x52, 0xcd, 0xe1, 0x0e, 0xe4, 0x87,
		0xf9, 0xb1, 0xf6, 0xb9, 0x50, 0x3d, 0x30, 0x76,
		0xda, 0xf8, 0x30, 0x0b, 0x0b, 0x46, 0x73, 0x6a,
		0x9d, 0x91, 0xd3, 0xc6, 0xb1, 0xfc, 0xf3, 0x2a,
		0xe9, 0xa3, 0x4c, 0x65, 0xd1, 0xcc, 0x37, 0x9d };

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20
	 * and pulling one ChaCha20 DRNG block plus one byte.
	 */
	uint8_t expected_block_and_byte[CHACHA20_KEY_SIZE + 1] = {
		0x0d, 0x7b, 0xa4, 0xec, 0x6c, 0xee, 0x5a, 0x9a,
		0xc5, 0x6c, 0x5b, 0xa8, 0x91, 0x05, 0x71, 0xc9,
		0x35, 0xca, 0x45, 0xdb, 0x8f, 0x10, 0xe4, 0x4a,
		0x3b, 0x53, 0x80, 0x98, 0x82, 0x9a, 0x3b, 0x27,
		0x5f };

	/* Generate with zero state */
	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_block));
	if (ret)
		return ret;
	if (memcmp(outbuf, expected_block, sizeof(expected_block)))
		return -EFAULT;

	/* Clear state of DRNG */
	memset(&drng->chacha20.key.u[0], 0, 48);

	/* Reseed with 2 blocks */
	ret = drng_chacha20_seed(&drng->chacha20, seed,
				 sizeof(expected_twoblocks));
	if (ret)
		return ret;
	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_twoblocks));
	if (ret)
		return ret;
	if (memcmp(outbuf, expected_twoblocks, sizeof(expected_twoblocks)))
		return -EFAULT;

	/* Clear state of DRNG */
	memset(&drng->chacha20.key.u[0], 0, 48);

	/* Reseed with 1 block and one byte */
	ret = drng_chacha20_seed(&drng->chacha20, seed,
				 sizeof(expected_block_and_byte));
	if (ret)
		return ret;
	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_block_and_byte));
	if (ret)
		return ret;
	if (memcmp(outbuf, expected_block_and_byte,
		   sizeof(expected_block_and_byte)))
		return -EFAULT;

	return 0;
}

static void drng_chacha20_dealloc(struct chacha20_drng *drng)
{
	memset_secure(drng, 0, sizeof(*drng));
	free(drng);
}

/**
 * Allocation of the DRBG state
 */
static int drng_chacha20_alloc(struct chacha20_drng **out)
{
	struct chacha20_drng *drng;
	uint32_t i, v = 0;
	int ret = 0;

	if (drng_chacha20_selftest()) {
		return -EFAULT;
	}

	ret = posix_memalign((void *)&drng, CHACHA20_DRNG_ALIGNMENT,
			     sizeof(*drng));
	if (ret) {
		return -ret;
	}

	/* prevent paging out of the memory state to swap space */
	ret = mlock(drng, sizeof(*drng));
	if (ret && errno != EPERM && errno != EAGAIN) {
		ret = -errno;
		goto err;
	}

	memset(drng, 0, sizeof(*drng));

	memcpy(&drng->chacha20.constants[0], "expand 32-byte k", 16);

	ret = drng_chacha20_rng_selftest(drng);
	if (ret)
		goto err;

	/* Update the state left by the self test */
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

err:
	drng_chacha20_dealloc(drng);
	return ret;
}

/***************************** ChaCha20 DRNG API *****************************/

DSO_PUBLIC
int drng_chacha20_reseed(struct chacha20_drng *drng, const uint8_t *inbuf,
			 uint32_t inbuflen)
{
	uint8_t seed[CHACHA20_KEY_SIZE * 2];
	int ret;
	uint32_t collected = 0;

	/* Entropy assumption: 1 data bit delivers one bit of entropy */
	ret = drng_getrandom_get(seed, CHACHA20_KEY_SIZE);
	if (ret < 0)
		return ret;

	if (ret) {
		collected = ret;

		ret = drng_chacha20_seed(&drng->chacha20, seed,
					 CHACHA20_KEY_SIZE);
		if (ret)
			return ret;
	}

	/* Entropy assumption: 2 data bits deliver one bit of entropy */
	ret = drng_jent_get(seed, sizeof(seed));
	if (ret < 0)
		return ret;

	if (ret) {
		collected += ret;

		ret = drng_chacha20_seed(&drng->chacha20, seed, sizeof(seed));
		if (ret)
			return ret;
	}

	/* Entropy assumption: 1 data bit delivers one bit of entropy */
	ret = drng_random_get(seed, CHACHA20_KEY_SIZE);
	if (ret < 0)
		return ret;

	if (ret) {
		collected += ret;

		ret = drng_chacha20_seed(&drng->chacha20, seed,
					 CHACHA20_KEY_SIZE);
		if (ret)
			return ret;
	}

	memset_secure(seed, 0, sizeof(seed));

	/* Internal noise sources must have delivered sufficient information */
	if (collected < CHACHA20_KEY_SIZE)
		return -EFAULT;

	if (inbuf && inbuflen)
		ret = drng_chacha20_seed(&drng->chacha20, inbuf, inbuflen);

	get_time(&drng->last_seeded, NULL);
	drng->generated_bytes = 0;

	return ret;
}

DSO_PUBLIC
void drng_chacha20_destroy(struct chacha20_drng *drng)
{
	drng_jent_dealloc();
	drng_random_dealloc();
	drng_chacha20_dealloc(drng);
}

DSO_PUBLIC
int drng_chacha20_init(struct chacha20_drng **drng)
{
	int ret = drng_chacha20_alloc(drng);

	if (ret)
		return ret;

	ret = drng_chacha20_reseed(*drng, NULL, 0);
	if (ret) {
		drng_chacha20_destroy(*drng);
		return ret;
	}

	return 0;
}

DSO_PUBLIC
int drng_chacha20_get(struct chacha20_drng *drng, uint8_t *outbuf,
		      uint32_t outbuflen)
{
	time_t now = 0;
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

DSO_PUBLIC
int drng_chacha20_versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ChaCha20 DRNG %d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
}

DSO_PUBLIC
uint32_t drng_chacha20_version(void)
{
	uint32_t version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
}
