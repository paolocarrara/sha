#include "../inc/sha1.h"

#define Ksize		0x50
#define Wsize		0x50
#define Hsize		0x05
#define ABCDEsize	0x05

static void setKH	(uint32_t *const, uint32_t *const);
static void schedule	(uint32_t *const, const uint8_t *const);
static uint32_t f	(const uint32_t, const uint32_t, const uint32_t, const uint32_t);

#ifdef ARCHITECTURE64
uint32_t *sha1 (uint8_t **const M, uint64_t N)
#else
uint32_t *sha1 (uint8_t **const M, uint32_t N)
#endif
{
	#ifdef ARCHITECTURE64
	uint64_t i;
	#else
	uint32_t i;
	#endif
	uint8_t j;

	/*Variables of the specifications*/
	uint32_t T;
	uint32_t *const H = malloc (Hsize*sizeof (uint32_t));
	uint32_t *const K = malloc (Ksize*sizeof (uint32_t));
	uint32_t *const W = malloc (Wsize*sizeof (uint32_t));
	uint32_t abcde[ABCDEsize];

	setKH (K, H);

	for (i = 0; i < N; i++) {

		schedule (W, M[i]);

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

	free (K);
	free (W);

	return H;
}

static void setKH (uint32_t *const K, uint32_t *const H)
{
	int8_t i = 80;

	while (i-->0) {
		if (i >= 60) {
			K[i] = 0xca62c1d6;
		}
		else if (i >= 40) {
			K[i] = 0x8f1bbcdc;
		}
		else if (i >= 20) {
			K[i] = 0x6ed9eba1;
		}
		else if (i >= 0) {
			K[i] = 0x5a827999;
		}
	}

	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;
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
	while (i < 80) {
		W[i] = ROTL32 (W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
		i++;
	}
}

static uint32_t f (const uint32_t b, const uint32_t c, const uint32_t d, const uint32_t t)
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
