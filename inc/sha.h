#ifndef SHA_H
#define SHA_H

#ifdef __cplusplus
extern "C" {
#endif

/*#ifdef: compilation problems due to only one identifier is legal/accepted, however the #if may not be a good solution..*/
#if __amd64__ ||  __amd64 || __x86_64__ || __x86_64
#define ARCHITECTURE64
#else
#define ARCHITECTURE32
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"

/*SHA block sizes in bytes*/
#define SHA_512_BLOCK	64
#define SHA_1024_BLOCK	128

/* SHA types */
#define SHA1_T		0x01
#define SHA224_T	0x02
#define SHA256_T	0x03
#define SHA384_T	0x04
#define SHA512_T	0x05
#define SHA512_224_T	0x06
#define SHA512_256_T	0x07

/**/
#define MIN_REALL_SZ	0x09
#define DFLT_FRST_BYT	0x80

/* parity macro/function */
#define PA(a, b, c) (a^b^c)

/* majority macro/function */
#define MA(a, b, c) ((a&b)^(a&c)^(b&c))

/* conditional macro/function */
#define CH(a, b, c) ((a&b)^(~a&c))

/* rot left for 32 bit values*/
#define ROTL32(a, l) (((a)<<(l)) + ((a)>>(0x20-l)))

#ifdef __cplusplus
}
#endif

#endif
