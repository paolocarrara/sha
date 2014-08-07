#ifndef SHA384_H
#define SHA384_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef ARCHITECTURE64
uint64_t *sha384 (uint8_t *, uint64_t);
#else
uint32_t *sha384 (uint8_t *, uint32_t);
#endif

#endif
