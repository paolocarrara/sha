#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __LP64__
uint8_t *generate_sha1 (uint8_t **const, uint64_t);
#else
uint8_t *generate_sha1 (uint8_t **const, uint32_t);
#endif

#endif
