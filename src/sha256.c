#include "../inc/sha256.h"

#define Ksize		0x40
#define Wsize		0x40
#define Hsize		0x08
#define ABCDEFGHsize	0x08

#ifdef ARCHITECTURE64
static uint8_t *padd512	(uint8_t *M, uint64_t *const sz);
#else
static uint8_t *padd512 (uint8_t *M, uint32_t *const sz);
#endif

#ifdef ARCHITECTURE64
static uint8_t **prsng512 (uint8_t * const M, const uint64_t sz, uint64_t *const N);
#else
static uint8_t **prsng512 (uint8_t * const M, const uint32_t sz, uint32_t *const N);
#endif

static void schedule	(uint32_t *const, const uint8_t *const);

#ifdef ARCHITECTURE64
uint32_t *sha256 (uint8_t *M, uint64_t sz)
#else
uint32_t *sha256 (uint8_t *M, uint32_t sz)
#endif
{
	#ifdef ARCHITECTURE64
	uint64_t i;
	uint64_t N;
	#else
	uint32_t i;
	uint32_t N;
	#endif
	uint8_t j;
	uint8_t **m;

	/* Variables of the specifications */
	uint32_t T1, T2;
	uint32_t *const H = malloc (Hsize*sizeof (uint32_t));
	uint32_t abcdefgh[ABCDEFGHsize];
	uint32_t W[Wsize];
	const uint32_t K[Ksize] =
       {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

	H[0] = 0x6a09e667;
	H[1] = 0xbb67ae85;
	H[2] = 0x3c6ef372;
	H[3] = 0xa54ff53a;
	H[4] = 0x510e527f;
	H[5] = 0x9b05688c;
	H[6] = 0x1f83d9ab;
	H[7] = 0x5be0cd19;

	/* preprocessing */
	M = padd512 (M, &sz);
	m = prsng512 (M, sz, &N);

	for (i = 0; i < N; i++) {

		schedule (W, m[i]);

		for (j = 0; j < 8; j++) {
			abcdefgh[j] = H[j];
		}

		for (j = 0; j < 64; j++) {
			T1 = abcdefgh[7] + E256_1 (abcdefgh[4]) + CH (abcdefgh[4], abcdefgh[5], abcdefgh[6]) + K[j] + W[j];
			T2 = E256_0 (abcdefgh[0]) + MA (abcdefgh[0], abcdefgh[1], abcdefgh[2]);
			abcdefgh[7] = abcdefgh[6];
			abcdefgh[6] = abcdefgh[5];
			abcdefgh[5] = abcdefgh[4];
			abcdefgh[4] = abcdefgh[3] + T1;
			abcdefgh[3] = abcdefgh[2];
			abcdefgh[2] = abcdefgh[1];
			abcdefgh[1] = abcdefgh[0];
			abcdefgh[0] = T1 + T2;
		}
		
		for (j = 0; j < 8; j++) {
			H[j] += abcdefgh[j];
		}
	}

	free (M);
	free (m);

	return H;
}

#ifdef ARCHITECTURE64
static uint8_t *padd512 (uint8_t *M, uint64_t *const sz)
#else
static uint8_t *padd512 (uint8_t *M, uint32_t *const sz)
#endif
{
	uint8_t r, g;

	r = ((*sz)+MIN_REALL_SZ)%SHA_512_BLOCK;
	g = SHA_512_BLOCK - r;

	M = realloc (M, (*sz)+g+MIN_REALL_SZ);

	M[(*sz)] = DFLT_FRST_BYT;
	memset (M+(*sz)+1, 0, g+4);
	M[(*sz)+g+8] = (*sz)*8 >> 0;
	M[(*sz)+g+7] = (*sz)*8 >> 8;
	M[(*sz)+g+6] = (*sz)*8 >> 16;
	M[(*sz)+g+5] = (*sz)*8 >> 24;
	(*sz) += g + MIN_REALL_SZ;

	return M;
}

#ifdef ARCHITECTURE64
static uint8_t **prsng512 (uint8_t * const M, const uint64_t sz, uint64_t *const N)
#else
static uint8_t **prsng512 (uint8_t * const M, const uint32_t sz, uint32_t *const N)
#endif
{
	uint8_t **blocks = NULL;
	#ifdef ARCHITECTURE64
	uint64_t i;
	#else
	uint32_t i;
	#endif

	(*N) = sz/SHA_512_BLOCK;
	blocks = malloc ((*N)*sizeof(uint8_t *));

	for (i = 0; i < (*N); i++)
			blocks[i] = M+(i*SHA_512_BLOCK);

	return blocks;
}

static void schedule (uint32_t *const W, const uint8_t *const M)
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		W[i] = M[i*4];
		W[i] = W[i] << 8;

		W[i] += M[i*4+1];
		W[i] = W[i] << 8;

		W[i] += M[i*4+2];
		W[i] = W[i] << 8;

		W[i] += M[i*4+3];
	}
	while (i < 64) {
		W[i] = S256_1 (W[i-2]) + W[i-7] + S256_0 (W[i-15]) + W[i-16];
		i++;
	}
}
