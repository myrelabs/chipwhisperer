#include "simplepass.h"
int seed=0x123;
int lcg() {
  seed = (seed+13)%(sizeof(secr)-1);
  return seed;
}
#define DUMMY 2
const uint8_t dummy[] = 
{
  0xff,0xff,0x00,0xff,
  0xff,0xff,0xff,0xff,
  0xff
};
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  seed = pass[DUMMY]; // FIXME! should be TRNG
  pass[DUMMY] = 0x33;
  door = DOOR_CLOSED;
  int neq = 0;
  for(int i=0;i<sizeof(secr)-1;i++) {
    int idx = lcg();
    neq |= (pass[idx] ^ secr[idx])&dummy[idx];
  }
  if(neq==0) {
    door = DOOR_OPEN;
  }
}
