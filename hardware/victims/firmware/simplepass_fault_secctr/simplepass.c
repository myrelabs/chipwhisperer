#include "simplepass.h"
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  int neq = 0;
  volatile int j = DOOR_OPEN + sizeof(secr)-1;
  int i=0;
  while(i<sizeof(secr)-1) {
    neq |= pass[i] ^ secr[i];
    i++;
    j--;
  }
  if(neq==0 && i==sizeof(secr)-1) {
    door = j;
  }
}
