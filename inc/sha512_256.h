#ifndef SHA512_256_H
#define SHA512_256_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef ARCHITECTURE64
uint64_t *sha512_256 (uint8_t *, uint64_t);
#else
uint32_t *sha512_256 (uint8_t *, uint32_t);
#endif

#endif
