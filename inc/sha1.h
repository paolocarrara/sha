#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <stdint.h>
#include "sha.h"

#ifdef __LP64__
uint32_t *sha1 (uint8_t **const, uint64_t);
#else
uint32_t *sha1 (uint8_t **const, uint32_t);
#endif

#endif
