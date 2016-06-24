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

#ifndef _CHACHA20_DRNG_H
#define _CHACHA20_DRNG_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

struct chacha20_drng;

DSO_PUBLIC
int drng_chacha20_init(struct chacha20_drng **drng);

DSO_PUBLIC
void drng_chacha20_destroy(struct chacha20_drng *drng);

DSO_PUBLIC
int drng_chacha20_get(struct chacha20_drng *drng, uint8_t *outbuf,
		      uint32_t outbuflen);

DSO_PUBLIC
int drng_chacha20_reseed(struct chacha20_drng *drng, const uint8_t *inbuf,
			 uint32_t inbuflen);

#ifdef __cplusplus
}
#endif

#endif /* _CHACHA20_DRNG_H */
