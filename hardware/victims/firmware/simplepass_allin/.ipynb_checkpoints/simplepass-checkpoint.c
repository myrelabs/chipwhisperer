#include "simplepass.h"
int seed = 7;
int lcg() {
  seed = (seed+23)%(sizeof(secr)-1);
  return seed;
}
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  seed = pass[3]; // FIXME! should be RNG
  door = DOOR_CLOSED;
  volatile int j = DOOR_OPEN + sizeof(secr)-1;
  for(int i=0;i<sizeof(secr)-1;i++) {
    int idx = lcg();
    pass[idx] ^= cmask[idx];
    j = j - 1 - (pass[idx] ^ secr_cmask[idx]);
  }
  door = j;
}
