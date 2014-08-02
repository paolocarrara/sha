#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef ARCHITECTURE64
uint32_t *sha1 (uint8_t *, uint64_t);
#else
uint32_t *sha1 (uint8_t *, uint32_t);
#endif

#endif
