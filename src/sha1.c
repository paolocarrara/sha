#include "../inc/sha1.h"



static inline void init_sha1 (uint32_t H[])
{
	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;
}

#ifdef __LP64__
uint8_t *generate_sha1 (uint8_t **M, uint64_t N)
#else
uint8_t *generate_sha1 (uint8_t **M, uint32_t N)
#endif
{
	uint32_t H[5];

	init_sha1 (H);

	return NULL;	
}
