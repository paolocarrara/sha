#include "../inc/sha.h"

#define TRUE	1
#define FALSE	0

/*
 *	Verify if the size of the message is less than the limit for its hash type.
*/
#ifdef ARCHITECTURE64
static uint8_t vrf_sz	(const uint64_t, const uint8_t);
#else
static uint8_t vrf_sz	(const uint32_t, const uint8_t);
#endif

/*
 *	Add the padding to the message. The last 4 bytes of the padding is the size of the message.
*/
#ifdef ARCHITECTURE64
static uint8_t *padd	(uint8_t *, uint64_t *const, const uint8_t);
#else
static uint8_t *padd	(uint8_t *, uint32_t *const, const uint8_t);
#endif

/*
 *	Parse the message in blocks of 64 or 128 bytes arccording to the hash function.
*/
#ifdef ARCHITECTURE64
static uint8_t **prsng	(uint8_t * const, const uint64_t, uint64_t *const, const uint8_t);
#else
static uint8_t **prsng	(uint8_t * const, const uint32_t, uint32_t *const, const uint8_t);
#endif

#ifdef ARCHITECTURE64
uint8_t **pre_process (uint8_t *M, uint64_t sz, uint64_t *const N, const uint8_t sha_t)
#else 
uint8_t **pre_process (uint8_t *M, uint32_t sz, uint32_t *const N, const uint8_t sha_t)
#endif
{
	uint8_t **Mp;

	if ( vrf_sz (sz, sha_t) ) {
		M = padd (M, &sz, sha_t);
		Mp = prsng (M, sz, N, sha_t);
	}
	else {
		/*TOO LONG MESSAGE*/
	}

	return Mp;
}

#ifdef ARCHITECTURE64
static uint8_t vrf_sz (const uint64_t sz, const uint8_t sha_t)
#else
static uint8_t vrf_sz (const uint32_t sz, const uint8_t sha_t)
#endif
{
	uint8_t bool = FALSE;

	switch (sha_t) {
		case SHA1_T:
		case SHA224_T:
		case SHA256_T:
		#ifdef ARCHITECTURE64
			if (sz < MAX_2_TO_64)
				bool = TRUE;
		#else
			break;
		#endif
		case SHA384_T:
		case SHA512_T:
		case SHA512_224_T:
		case SHA512_256_T:
			if (sz < MAX_2_TO_128)
				bool = TRUE;
			break;
	}

	return bool;
}

#ifdef ARCHITECTURE64
static uint8_t *padd (uint8_t *M, uint64_t *const sz, const uint8_t sha_t)
#else
static uint8_t *padd (uint8_t *M, uint32_t *const sz, const uint8_t sha_t)
#endif
{	
	uint8_t r;
	uint8_t g;
	
	if (sha_t == SHA1_T || sha_t == SHA224_T || sha_t == SHA256_T) {
		M = realloc (M, (*sz)+1);
		M[(*sz)] = 0x80;
		r = ((*sz)+9)%SHA_512_BLOCK;
		g = SHA_512_BLOCK - r;
	}
	else if (sha_t == SHA384_T || sha_t == SHA512_T || sha_t == SHA512_224_T || sha_t == SHA512_256_T) {
		M = realloc (M, (*sz)+1);
		M[(*sz)] = 0x80;
		r = ((*sz)+8)%SHA_1024_BLOCK;
		g = SHA_1024_BLOCK - r;
	}
	else {
		/*SHA_T NOT FOUND*/
	}

	M = realloc (M, (*sz)+g+9);


	if (sha_t == SHA1_T || sha_t == SHA224_T || sha_t == SHA256_T) {
		memset (M+((*sz)+1), 0, g+4);
		M[(*sz)+g+8] = (*sz)*8 >> 0;
		M[(*sz)+g+7] = (*sz)*8 >> 8;
		M[(*sz)+g+6] = (*sz)*8 >> 16;
		M[(*sz)+g+5] = (*sz)*8 >> 24;
	}
	else if (sha_t == SHA384_T || sha_t == SHA512_T || sha_t == SHA512_224_T || sha_t == SHA512_256_T) {
		memset (M+(*sz)+1, 0, g-8);
		M[SHA_1024_BLOCK-1] = (*sz)*8;
		M[SHA_1024_BLOCK-2] = (*sz)*8 >> 8;
		M[SHA_1024_BLOCK-3] = (*sz)*8 >> 16;
		M[SHA_1024_BLOCK-4] = (*sz)*8 >> 24;
		M[SHA_1024_BLOCK-5] = (*sz)*8 >> 32;
		M[SHA_1024_BLOCK-6] = (*sz)*8 >> 40;
		M[SHA_1024_BLOCK-7] = (*sz)*8 >> 48;
		M[SHA_1024_BLOCK-8] = (*sz)*8 >> 56;
	}
	
	(*sz) += g+9;

	return M;
}

#ifdef ARCHITECTURE64
static uint8_t **prsng (uint8_t * const M, const uint64_t sz, uint64_t *const N, const uint8_t sha_t)
#else
static uint8_t **prsng (uint8_t * const M, const uint32_t sz, uint32_t *const N, const uint8_t sha_t)
#endif
{
	uint8_t **blocks = NULL;
	#ifdef ARCHITECTURE64
	uint64_t i;
	#else
	uint32_t i;
	#endif

	if (sha_t == SHA1_T || sha_t == SHA224_T || sha_t == SHA256_T) {
		(*N) = sz/SHA_512_BLOCK;
		blocks = malloc ((*N)*sizeof(uint8_t *));
		for (i = 0; i < (*N); i++)
			blocks[i] = M+(i*64);
	}
	else if (sha_t == SHA384_T || sha_t == SHA512_T || sha_t == SHA512_224_T || sha_t == SHA512_256_T) {
		(*N) = sz/SHA_1024_BLOCK;
		blocks = malloc ((*N)*sizeof(uint8_t *));
		for (i = 0; i < (*N); i++)
			blocks[i] = M+(i*128);
	}	

	return blocks;
}
