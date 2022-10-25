#include "simplepass.h"
uint8_t vmask[sizeof(secr)] = {0};
uint8_t secr_vmask[sizeof(secr)] = {0};
int initialized = 0;
void init(unsigned* seed) {
  if (!initialized)
  {
    srand(seed[0]);
  }
  initialized = 1;
}
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  init((unsigned*)pass);
  for(int i=0;i<sizeof(secr);i++) {
    vmask[i]      = (uint8_t)rand();
    secr_vmask[i] = secr[i] ^ vmask[i];
  }
  door = DOOR_CLOSED;
  uint8_t neq = 0;
  for(int i=0;i<sizeof(secr);i++) {
    pass[i] ^= vmask[i];
    neq     |= pass[i] ^ secr_vmask[i];
  }
  if(neq==0) {
    door = DOOR_OPEN;
  }
}
