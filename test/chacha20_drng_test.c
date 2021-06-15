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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <error.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#include "chacha20_drng.h"

static uint8_t hex_char(unsigned int bin, int u)
{
	uint8_t hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	uint8_t hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/**
 * Convert binary string into hex representation
 * @bin [in] input buffer with binary data
 * @binlen [in] length of bin
 * @hex [out] output buffer to store hex data
 * @hexlen [in] length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u [in] case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const uint8_t *bin, uint32_t binlen,
		    char *hex, uint32_t hexlen, int u)
{
	uint32_t i = 0;
	uint32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

static void bin2print(const uint8_t *bin, uint32_t binlen,
		      const char *explanation)
{
	char *hex;
	uint32_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	fprintf(stdout, "%s: %s\n", explanation, hex);
	free(hex);
}

static int basic_test(void)
{
	struct chacha20_drng *drng;
	uint8_t buf[10];
	char version[30];
	int ret;

	drng_chacha20_versionstring(version, sizeof(version));
	printf("Obtained version string: %s\n", version);
	printf("Obtained version number: %u\n", drng_chacha20_version());

	ret = drng_chacha20_init(&drng);
	if (ret) {
		printf("Allocation failed: %d\n", ret);
		return 1;
	}

	if (drng_chacha20_get(drng, buf, sizeof(buf))) {
		printf("Getting random numbers failed\n");
		return 1;
	}

	bin2print(buf, sizeof(buf), "Random number");

	if (drng_chacha20_reseed(drng, buf, sizeof(buf))) {
		printf("Re-seeding failed\n");
		return 1;
	}

	if (drng_chacha20_get(drng, buf, sizeof(buf))) {
		printf("Getting random numbers failed\n");
		return 1;
	}

	bin2print(buf, sizeof(buf), "Random number after reseed");

	drng_chacha20_destroy(drng);

	return 0;
}

static int gen_test(void)
{
	struct chacha20_drng *drng;

	if (drng_chacha20_init(&drng)) {
		printf("Allocation failed\n");
		return 1;
	}

	while(1) {
		uint8_t tmp[32];

		if (drng_chacha20_get(drng, tmp, sizeof(tmp))) {
			printf("Getting random numbers failed\n");
			return 1;
		}
		fwrite(&tmp, sizeof(tmp), 1, stdout);
	}

	drng_chacha20_destroy(drng);

	return 0;
}

static inline uint64_t cp_ts2u64(struct timespec *ts)
{
	uint64_t upper = ts->tv_sec;

	upper = upper << 32;
	return (upper | ts->tv_nsec);
}

/*
 * This is x86 specific to reduce the CPU jitter
 */
static inline void cp_cpusetup(void)
{
#ifdef __X8664___
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
#endif
}

static inline void cp_get_nstime(struct timespec *ts)
{
	clock_gettime(CLOCK_REALTIME, ts);
}

static inline void cp_start_time(struct timespec *ts)
{
	cp_cpusetup();
	cp_get_nstime(ts);
}

static inline void cp_end_time(struct timespec *ts)
{
	cp_get_nstime(ts);
}

/*
 * Convert an integer value into a string value that displays the integer
 * in either bytes, kB, or MB
 *
 * @bytes value to convert -- input
 * @str already allocated buffer for converted string -- output
 * @strlen size of str
 */
static void cp_bytes2string(uint64_t bytes, char *str, size_t strlen)
{
	if (1UL<<30 < bytes) {
		uint64_t abs = (bytes>>30);
		uint64_t part = ((bytes - (abs<<30)) / (10000000));
		snprintf(str, strlen, "%lu.%lu GB", (unsigned long)abs,
			 (unsigned long)part);
		return;

	} else if (1UL<<20 < bytes) {
		uint64_t abs = (bytes>>20);
		uint64_t part = ((bytes - (abs<<20)) / (10000));
		snprintf(str, strlen, "%lu.%lu MB", (unsigned long)abs,
			 (unsigned long)part);
		return;
	} else if (1UL<<10 < bytes) {
		uint64_t abs = (bytes>>10);
		uint64_t part = ((bytes - (abs<<10)) / (10));
		snprintf(str, strlen, "%lu.%lu kB", (unsigned long)abs,
			 (unsigned long)part);
		return;
	}
	snprintf(str, strlen, "%lu B", (unsigned long)bytes);
	str[strlen - 1] = '\0';
}

static void cp_print_status(uint64_t rounds, uint64_t tottime,
			    uint32_t byteperop, int raw)
{
	uint64_t processed_bytes = rounds * byteperop;
	uint64_t totaltime = tottime>>32;
	uint64_t ops = 0;
	char *testname = "ChaCha20 DRNG";

	if (!totaltime) {
		printf("%-35s | untested\n", testname);
		return;
	}

	ops = rounds / totaltime;

	if (raw) {
		printf("%s,%lu,%lu,%lu\n", testname,
		       (unsigned long)processed_bytes,
		       (unsigned long)(processed_bytes/totaltime),
		       (unsigned long)ops);
	} else {
		#define VALLEN 23
		char byteseconds[VALLEN + 1];

		memset(byteseconds, 0, sizeof(byteseconds));
		cp_bytes2string((processed_bytes / totaltime), byteseconds,
				(VALLEN + 1));
		printf("%-20s|%12lu bytes|%*s/s|%lu ops/s\n",
		       testname, (unsigned long)processed_bytes, VALLEN,
		       byteseconds, (unsigned long)ops);
	}
}

static int time_test(uint64_t chunksize)
{
	uint64_t nano = 1;
	uint64_t testduration;
	uint64_t totaltime = 0;
	uint64_t rounds = 0;
	unsigned int i = 0;
	struct chacha20_drng *drng;
	uint8_t *tmp;

	tmp = malloc(chunksize);
	if (!tmp) {
		printf("Allocation of memory failed\n");
		return 1;
	}

	if (drng_chacha20_init(&drng)) {
		printf("Allocation of DRNG failed\n");
		free(tmp);
		return 1;
	}

	nano = nano << 32;
	testduration = nano * 10;

	/* prime the test */
	for (i = 0; i < 10; i++)
		drng_chacha20_get(drng, tmp, chunksize);

	while (totaltime < testduration) {
		struct timespec start;
		struct timespec end;

		cp_get_nstime(&start);
		drng_chacha20_get(drng, tmp, chunksize);
		cp_get_nstime(&end);
		totaltime += (cp_ts2u64(&end) - cp_ts2u64(&start));
		rounds++;
	}

	drng_chacha20_destroy(drng);
	free(tmp);

	cp_print_status(rounds, totaltime, chunksize, 0);

	return 0;
}

static int generate_bytes(uint32_t bytes, uint32_t blocksize)
{
	struct chacha20_drng *drng;
	unsigned char tmp[4096];

	if (blocksize > sizeof(tmp)) {
		printf("blocksize %u too large (max %lu)\n", blocksize,
		       sizeof(tmp));
		return 1;
	}

	if (drng_chacha20_init(&drng)) {
		printf("Allocation of DRNG failed\n");
		return 1;
	}

	while (bytes) {
		uint32_t todo = (bytes > blocksize) ? blocksize : bytes;
		int ret = drng_chacha20_get(drng, tmp, todo);

		if (ret) {
			printf("DRNG generation failed (ret: %d)\n", ret);
			return ret;
		}
		fwrite(&tmp, todo, 1, stdout);

		bytes -= todo;
	}

	drng_chacha20_destroy(drng);

	/* memset_secure(tmp) */
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		if (basic_test()) {
			printf("Basic test failed\n");
			return 1;
		}
		printf("Basic test passed\n");
	} else if (!strncmp(argv[1], "-g", 2)) {
		gen_test();
	} else if (!strncmp(argv[1], "-o", 2) && (argc == 3 || argc == 4)) {
		unsigned long bytes = strtoul(argv[2], NULL, 10);
		unsigned long blocksize = 4096;

		if (argc == 4) {
			blocksize = strtoul(argv[3], NULL, 10);
		}

		if (bytes == ULONG_MAX && errno == ERANGE) {
			printf("strtoul conversion failed\n");
			return 1;
		}
		if (bytes > UINT_MAX || blocksize > UINT_MAX) {
			printf("requested size too long\n");
			return 1;
		}

		return generate_bytes((uint32_t)bytes, (uint32_t)blocksize);
	} else if (!strncmp(argv[1], "-t", 2)) {
		unsigned long chunksize = 32;

		if (argc == 3) {
			chunksize = strtoul(argv[2], NULL, 10);
			if (chunksize == ULONG_MAX && errno == ERANGE) {
				printf("strtoul conversion failed\n");
				return 1;
			}
		}
		time_test(chunksize);
	} else {
		printf("Unknown test\n");
	}

	return 0;
}
