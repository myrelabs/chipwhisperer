#include "simplepass.h"
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  uint32_t neq = 0;
  for(int i=0;i<sizeof(secr)-1;i++) {
    neq |= pass3[i] ^ secr3[i];
  }
  if((neq&0xffu)==0) {
    door = DOOR_OPEN;
  }
}
