#include "../inc/sha512_224.h"

#define Ksize		0x50
#define Wsize		0x50
#define Hsize		0x04
#define ABCDEFGHsize	0x08

#ifdef ARCHITECTURE64
static uint8_t *padd1024	(uint8_t *M, uint64_t *const sz);
#else
static uint8_t *padd1024	(uint8_t *M, uint32_t *const sz);
#endif

#ifdef ARCHITECTURE64
static uint8_t **prsng1024	(uint8_t * const M, const uint64_t sz, uint64_t *const N);
#else
static uint8_t **prsng1024	(uint8_t * const M, const uint32_t sz, uint32_t *const N);
#endif

static void schedule		(uint64_t *const, const uint8_t *const);

#ifdef ARCHITECTURE64
uint64_t *sha512_224 (uint8_t *M, uint64_t sz)
{
	uint64_t i;
	uint64_t N;
	uint8_t j;
	uint8_t **m;

	/* Variables of the specifications */
	uint64_t T1, T2;
	uint64_t *const H = malloc (Hsize*sizeof (uint64_t));
	uint64_t Haux1;
	uint64_t Haux2;
	uint64_t Haux3;
	uint64_t Haux4;
	uint64_t abcdefgh[ABCDEFGHsize];
	uint64_t W[Wsize];
	const uint64_t K[Ksize] =
		{0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

	H[0] = 0x8c3d37c819544da2;
	H[1] = 0x73e1996689dcd4d6;
	H[2] = 0x1dfab7ae32ff9c82;
	H[3] = 0x679dd514582f9fcf;
	Haux1 = 0x0f6d2b697bd44da8;
	Haux2 = 0x77e36f7304c48942;
	Haux3 = 0x3f9d85a86a1d36c8;
	Haux4 = 0x1112e6ad91d692a1;

	/* preprocessing */
	M = padd1024 (M, &sz);
	m = prsng1024 (M, sz, &N);

	for (i = 0; i < N; i++) {

		schedule (W, m[i]);

		for (j = 0; j < 4; j++) {
			abcdefgh[j] = H[j];
		}
		abcdefgh[4] = Haux1;
		abcdefgh[5] = Haux2;
		abcdefgh[6] = Haux3;
		abcdefgh[7] = Haux4;

		for (j = 0; j < 80; j++) {
			T1 = abcdefgh[7] + E512_1 (abcdefgh[4]) + CH (abcdefgh[4], abcdefgh[5], abcdefgh[6]) + K[j] + W[j];
			T2 = E512_0 (abcdefgh[0]) + MA (abcdefgh[0], abcdefgh[1], abcdefgh[2]);
			abcdefgh[7] = abcdefgh[6];
			abcdefgh[6] = abcdefgh[5];
			abcdefgh[5] = abcdefgh[4];
			abcdefgh[4] = abcdefgh[3] + T1;
			abcdefgh[3] = abcdefgh[2];
			abcdefgh[2] = abcdefgh[1];
			abcdefgh[1] = abcdefgh[0];
			abcdefgh[0] = T1 + T2;
		}		

		for (j = 0; j < 4; j++) {
			H[j] += abcdefgh[j];
		}
		Haux1 = abcdefgh[4];
		Haux2 = abcdefgh[5];
		Haux3 = abcdefgh[6];
		Haux4 = abcdefgh[7];
	}

	H[3] = H[3]>>32;


	free (M);
	free (m);

	return H;
}
#else
uint64_t *sha512 (uint8_t *M, uint32_t sz)
{
	printf ("Error: no sha512 hash encryption function for 32bit architecture\n");
	return NULL;
}
#endif

#ifdef ARCHITECTURE64
static uint8_t *padd1024 (uint8_t *M, uint64_t *const sz)
#else
static uint8_t *padd1024 (uint8_t *M, uint32_t *const sz) /*fix this part, if sz is too big, the (*sz)*8 part causes buffer overflow*/
#endif
{
	uint8_t r, g;

	r = ((*sz)+MIN_REALL_SZ2)%SHA_1024_BLOCK;
	g = SHA_1024_BLOCK - r;

	M = realloc (M, (*sz)+g+MIN_REALL_SZ2);

	M[(*sz)] = DFLT_FRST_BYT;
	memset (M+(*sz)+1, 0, g+12);
	M[(*sz)+g+16] = (*sz)*8 >> 0;
	M[(*sz)+g+15] = (*sz)*8 >> 8;
	M[(*sz)+g+14] = (*sz)*8 >> 16;
	M[(*sz)+g+13] = (*sz)*8 >> 24;
	M[(*sz)+g+12] = (*sz)*8 >> 32;
	M[(*sz)+g+11] = (*sz)*8 >> 40;
	M[(*sz)+g+10] = (*sz)*8 >> 48;
	M[(*sz)+g+9] = (*sz)*8 >> 56;
	(*sz) += g + MIN_REALL_SZ2;

	return M;
}

#ifdef ARCHITECTURE64
static uint8_t **prsng1024 (uint8_t * const M, const uint64_t sz, uint64_t *const N)
#else
static uint8_t **prsng1024 (uint8_t * const M, const uint32_t sz, uint32_t *const N)
#endif
{
	uint8_t **blocks = NULL;
	#ifdef ARCHITECTURE64
	uint64_t i;
	#else
	uint32_t i;
	#endif

	(*N) = sz/SHA_1024_BLOCK;
	blocks = malloc ((*N)*sizeof(uint8_t *));

	for (i = 0; i < (*N); i++)
			blocks[i] = M+(i*SHA_1024_BLOCK);

	return blocks;
}

static void schedule (uint64_t *const W, const uint8_t *const M)
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		W[i] = M[i*8];
		W[i] = W[i] << 8;

		W[i] += M[i*8+1];
		W[i] = W[i] << 8;

		W[i] += M[i*8+2];
		W[i] = W[i] << 8;

		W[i] += M[i*8+3];
		W[i] = W[i] << 8;

		W[i] += M[i*8+4];
		W[i] = W[i] << 8;

		W[i] += M[i*8+5];
		W[i] = W[i] << 8;

		W[i] += M[i*8+6];
		W[i] = W[i] << 8;

		W[i] += M[i*8+7];
	}
	while (i < 80) {
		W[i] = S512_1 (W[i-2]) + W[i-7] + S512_0 (W[i-15]) + W[i-16];
		i++;
	}
}
