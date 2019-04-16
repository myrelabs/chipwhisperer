#ifndef MT_H
#define MT_H

#include <stdint.h>

/* Seed MT */
void mt_seed(uint32_t seed);

/* Extract word from MT */
uint32_t mt_extract();

#endif /* MT_H */
