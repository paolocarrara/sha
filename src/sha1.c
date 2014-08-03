#include "../inc/sha1.h"

#define Ksize		0x50
#define Wsize		0x50
#define Hsize		0x05
#define ABCDEsize	0x05

#ifdef ARCHITECTURE64
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t *padd512	(uint8_t *, uint64_t *const);
#else
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t *padd512	(uint8_t *, uint32_t *const);
#endif

#ifdef ARCHITECTURE64
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t **prsng512 (uint8_t * const M, const uint64_t sz, uint64_t *const N);
#else
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t **prsng512 (uint8_t * const M, const uint32_t sz, uint32_t *const N);
#endif

__attribute__((always_inline, optimize("Ofast"), nonnull, pure, hot))
static inline void schedule	(uint32_t *const, const uint8_t *const);

__attribute__((always_inline, optimize("Ofast"), warn_unused_result, hot))
static inline uint32_t f	(const uint32_t, const uint32_t, const uint32_t, const uint32_t);


#ifdef ARCHITECTURE64
__attribute__((flatten, optimize("Ofast","-funroll-loops")))
uint32_t *sha1 (uint8_t *M, uint64_t sz)
#else
__attribute__((flatten, optimize("Ofast","-funroll-loops")))
uint32_t *sha1 (uint8_t *M, uint32_t sz)
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
	
	/*Variables of the specifications*/
	uint32_t T;
	uint32_t *const H = malloc (Hsize*sizeof (uint32_t));
	uint32_t abcde [ABCDEsize];
	uint32_t W [Wsize];
	uint32_t K [Ksize] = {	[0 ... 19] = 0x5a827999, 
				[20 ... 39] = 0x6ed9eba1, 
				[40 ... 59] = 0x8f1bbcdc, 
				[60 ... 79] = 0xca62c1d6 };

	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;
	
	/* preprocessing */
	M = padd512 (M, &sz);
	m = prsng512 (M, sz, &N);

	for (i = 0; i < N; i++) {

		schedule (W, m[i]);

		for (j = 0; j < 5; j++) {
			abcde[j] = H[j];
		}

		for (j = 0; j < 80; j++) {
			T = ROTL32(abcde[0], 5) + f(abcde[1], abcde[2], abcde[3], j) + abcde[4] + K[j] + W[j];
			abcde[4] = abcde[3];
			abcde[3] = abcde[2];
			abcde[2] = ROTL32(abcde[1], 30);
			abcde[1] = abcde[0];
			abcde[0] = T;
		}
		
		for (j = 0; j < 5; j++) {
			H[j] += abcde[j];
		}
	}
	
	free (m);
	free (M);

	return H;
}
#ifdef ARCHITECTURE64
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t *padd512 (uint8_t *M, uint64_t *const sz)
#else
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t *padd512 (uint8_t *M, uint32_t *const sz)
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
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t **prsng512 (uint8_t * const M, const uint64_t sz, uint64_t *const N)
#else
__attribute__((always_inline, nonnull, warn_unused_result, optimize("Ofast")))
static inline uint8_t **prsng512 (uint8_t * const M, const uint32_t sz, uint32_t *const N)
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

__attribute__((always_inline, optimize("Ofast"), nonnull, pure, hot))
static inline void schedule (uint32_t *const W, const uint8_t *const M)
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
	while (i < 80) {
		W[i] = ROTL32 (W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
		i++;
	}
}

__attribute__((always_inline, optimize("Ofast"), warn_unused_result, hot))
static inline uint32_t f (const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t t)
{
	if (t >= 60) {
		return PA (b, c, d);
	}
	else if (t >= 40) {
		return MA (b, c, d);
	}
	else if (t >= 20) {
		return PA (b, c, d);
	}
	else {
		return CH (b, c, d);
	}
}
