#include "simplepass.h"
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  volatile int j = DOOR_OPEN + sizeof(secr)-1;
  int i=0;
  while(i<sizeof(secr)-1) {
    i++;
    j = j - 1 - (pass[i] ^ secr[i]);
  }
  if(i==sizeof(secr)-1) { // NOTE: useless
    door = j;
  }
}
