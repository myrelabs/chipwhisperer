#include "simplepass.h"
void validate(uint8_t* pass,uint16_t* pass2,uint32_t* pass3) {
  door = DOOR_CLOSED;
  int neq = 0;
  for(int i=0;i<sizeof(secr);i++) {
    volatile uint8_t x = pass[i];
    x   ^= cmask[i];
    neq |= x ^ secr_cmask[i]; 
  }
  if(neq==0) {
    door = DOOR_OPEN;
  }
}
