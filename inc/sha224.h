#ifndef SHA224_H
#define SHA224_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef ARCHITECTURE64
__attribute__((flatten, optimize("Ofast","-funroll-loops")))
uint32_t *sha224 (uint8_t *, uint64_t);
#else
__attribute__((flatten, optimize("Ofast","-funroll-loops")))
uint32_t *sha224 (uint8_t *, uint32_t);
#endif

#endif
