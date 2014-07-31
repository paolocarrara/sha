#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"

#define SHA_512_BLOCK	64
#define SHA_1024_BLOCK	128

#define MAX_2_TO_64	0xffffffffffffffff
#define MAX_2_TO_128	0xffffffffffffffff/*ffffffffffffffff*/

#define SHA1_T		0x1
#define SHA224_T	0x2
#define SHA256_T	0x3
#define SHA384_T	0x4
#define SHA512_T	0x5
#define SHA512_224_T	0x6
#define SHA512_256_T	0x7

#ifdef __LP64__
uint8_t **pre_process	(uint8_t *, uint64_t, uint64_t *, uint8_t);
uint8_t *generate	(uint8_t **, uint64_t, uint8_t);
#else
uint8_t **pre_process	(uint8_t *, uint32_t, uint32_t *, uint8_t);
uint8_t *generate	(uint8_t **, uint32_t, uint8_t);
#endif

#endif
