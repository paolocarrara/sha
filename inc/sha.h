#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stdlib.h>

/*Preprocessing*/
uint8_t  *sha_padding		(uint8_t *);
uint8_t **sha_parsing		(uint8_t *);
void set_initialization_values	(void);

/*Hash computation*/

#endif
