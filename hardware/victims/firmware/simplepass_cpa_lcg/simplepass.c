#include "simplepass.h"
int seed=0x123;
int lcg() {
  seed = (seed+13)%(sizeof(secr)-1);
  return seed;
}
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  int neq = 0;
  for(int i=0;i<sizeof(secr)-1;i++) {
    int idx = lcg();
    neq |= pass[idx] ^ secr[idx];
  }
  if(neq==0) {
    door = DOOR_OPEN;
  }
}
