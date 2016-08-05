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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <error.h>
#include <errno.h>

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

	drng_chacha20_versionstring(version, sizeof(version));
	printf("Obtained version string: %s\n", version);
	printf("Obtained version number: %u\n", drng_chacha20_version());

	if (drng_chacha20_init(&drng)) {
		printf("Allocation failed\n");
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

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (argc == 1) {
		if (basic_test()) {
			printf("Basic test failed\n");
			return 1;
		}
	} else {
		gen_test();
	}

	printf("All tests passed\n");
}
