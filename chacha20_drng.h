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

#ifndef _CHACHA20_DRNG_H
#define _CHACHA20_DRNG_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

struct chacha20_drng;

/**
 * DOC: ChaCha20 DRNG API
 *
 * API function calls used to invoke ChaCha20 DRNG.
 */

/**
 * drng_chacha20_init() - Initialization of a ChaCha20 DRNG cipher handle
 *
 * @drng: [out] cipher handle allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * Before the allocation is performed, a self test regarding the correct
 * operation of the ChaCha20 cipher is performed. Only when the self test
 * succeeds, the allocation operation is performed.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * As part of the allocation, the seed source is initialized.
 *
 * The state of the DRNG is automatically seeded from the internal
 * noise source. Thus, the caller may immediately generate random numbers
 * without providing (additional) seed.
 *
 * @return 0 upon success; < 0 on error
 */
DSO_PUBLIC
int drng_chacha20_init(struct chacha20_drng **drng);

/**
 * drng_chacha20_destroy() - Secure deletion of the ChaCha20 DRNG cipher handle
 *
 * @drng: [in] cipher handle to be deallocated
 *
 * During the deallocation operation, the seed source is properly
 * disposed of.
 *
 * Also, the used memory is securely erased.
 *
 */
DSO_PUBLIC
void drng_chacha20_destroy(struct chacha20_drng *drng);

/**
 * drng_chacha20_get() - Obtain random numbers
 *
 * @drng: [in] allocated ChaCha20 cipher handle
 * @outbuf: [out] allocated buffer that is to be filled with random numbers
 * @outbuflen: [in] length of outbuf indicating the size of the random
 *	number byte string to be generated
 *
 * Generate random numbers and fill the buffer provided by the caller.
 *
 * Before each request of random numbers, a high-resolution time stamp is
 * mixed into the random number generator state.
 *
 * If the last (re)seeding operation is longer than 600 seconds ago or
 * more than 1GB of random numbers were generated, an automated
 * reseed is performed.
 *
 * After the generation of random numbers, the internal state of the ChaCha20
 * DRNG is completely re-created using ChaCha20 to provide enhanced backtracking
 * resistance. I.e. if the state of the DRNG becomes known after generation
 * of random numbers, an attacker cannot deduce the already generated
 * random numbers.
 *
 * @return 0 upon success; < 0 on error
 */
DSO_PUBLIC
int drng_chacha20_get(struct chacha20_drng *drng, uint8_t *outbuf,
		      uint32_t outbuflen);

/**
 * drng_chacha20_reseed() - Reseed the ChaCha20 DRNG
 *
 * @drng: [in] allocated ChaCha20 cipher handle
 * @inbuf: [in] buffer with the seed data
 * @inbuflen: [in] length of inbuf
 *
 * When calling the function, the DRNG is first seeded from its internal
 * noise sources. This is followed by seeding the DRNG with the caller-provided
 * data.
 *
 * @return 0 upon succes; < 0 on error
 */
DSO_PUBLIC
int drng_chacha20_reseed(struct chacha20_drng *drng, const uint8_t *inbuf,
			 uint32_t inbuflen);

/**
 * drng_chacha20_versionstring() - obtain version string of ChaCha20 DRNG
 *
 * @buf: [out] buffer to place version string into
 * @buflen: [in] length of buffer
 *
 * @buf is filled with a string of the form "chacha20 DRNG X.Y.Z".  Care
 * should be taken to provide a large enough buffer taking in to account that
 * X, Y, and/or Z may be multiple characters.
 *
 * @return status of snprintf(3).  < 0 on error, otherwise length of written
 * string.  See snprintf(3) for details on truncation.
 */
DSO_PUBLIC
int drng_chacha20_versionstring(char *buf, size_t buflen);

/**
 * drng_chacha20_version() - return machine-usable version number of ChaCha20
 *			     DRNG
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * @return Version number of ChaCha20 DRNG
 */
DSO_PUBLIC
uint32_t drng_chacha20_version(void);

#ifdef __cplusplus
}
#endif

#endif /* _CHACHA20_DRNG_H */
