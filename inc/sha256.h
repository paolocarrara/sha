#ifndef SHA256_H
#define SHA256_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef ARCHITECTURE64
uint32_t *sha256 (uint8_t *, uint64_t);
#else
uint32_t *sha256 (uint8_t *, uint32_t);
#endif

#endif
