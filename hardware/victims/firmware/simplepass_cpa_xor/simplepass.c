#include "simplepass.h"
void validate(uint8_t* pass,uint16_t* pass2,uint32_t* pass3) {
  door = DOOR_CLOSED;
  int neq = 0;
  for(int i=0;i<sizeof(secr);i++) {
    neq |= pass[i] ^ secr[i];
  }
  if(neq==0) {
    door = DOOR_OPEN;
  }
}
