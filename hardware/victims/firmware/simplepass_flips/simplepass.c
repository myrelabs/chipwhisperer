#include "simplepass.h"
void validate(uint8_t* pass) {
  door = DOOR_CLOSED;
  for(int i=0;i<sizeof(secr);i++) {
    if(pass[i] != secr[i]) {
      return;
    }
  }
  door = DOOR_OPEN;
}
