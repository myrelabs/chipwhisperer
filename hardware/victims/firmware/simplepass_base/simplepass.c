#include "simplepass.h"
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  for(int i=0;i<sizeof(secr);i++) {
    if(pass[i] != secr[i]) {
      return;
    }
  }
  door = DOOR_OPEN;
}
