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
#include "sha224.h"
#include "sha256.h"
#include "sha512.h"
#include "sha512_224.h"
#include "sha512_256.h"

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
#define MIN_REALL_SZ2	0x11
#define DFLT_FRST_BYT	0x80

/* parity macro/function */
#define PA(a, b, c) (a^b^c)

/* majority macro/function */
#define MA(a, b, c) ((a&b)^(a&c)^(b&c))

/* conditional macro/function */
#define CH(a, b, c) ((a&b)^(~a&c))

/* rot left, for 32 bit values */
#define ROTL32(a, l) (((a)<<(l)) + ((a)>>(0x20-l)))

/* rot right, for 32 bit values */
#define ROTR32(a, l) (((a)>>(l)) + ((a)<<(0x20-l)))

/* rot right, for 64 bit values */
#define ROTR64(a, l) (((a)>>(l)) + ((a)<<(0x40-l)))

/* shift right*/
#define SHR(a, l) ((a)>>(l))

#define E256_0(a) ((ROTR32(a, 2))^(ROTR32(a, 13))^(ROTR32(a, 22)))
#define E256_1(a) ((ROTR32(a, 6))^(ROTR32(a, 11))^(ROTR32(a, 25)))
#define S256_0(a) ((ROTR32(a, 7))^(ROTR32(a, 18))^(SHR(a, 3)))
#define S256_1(a) ((ROTR32(a, 17))^(ROTR32(a, 19))^(SHR(a, 10)))

#define E512_0(a) ((ROTR64(a, 28))^(ROTR64(a, 34))^(ROTR64(a, 39)))
#define E512_1(a) ((ROTR64(a, 14))^(ROTR64(a, 18))^(ROTR64(a, 41)))
#define S512_0(a) ((ROTR64(a, 1))^(ROTR64(a, 8))^(SHR(a, 7)))
#define S512_1(a) ((ROTR64(a, 19))^(ROTR64(a, 61))^(SHR(a, 6)))

#ifdef __cplusplus
}
#endif

#endif
