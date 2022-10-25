#include "simplepass.h"
#define SAFEBOOL_TRUE  0xA5A5A5A5A5A5A5A5ull
#define SAFEBOOL_FALSE 0x5A5A5A5A5A5A5A5Aull
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  door = DOOR_CLOSED;
  volatile uint64_t good = SAFEBOOL_TRUE;
  //volatile int good = SAFEBOOL_TRUE;
  for(int i=0;i<sizeof(secr);i++) {
    if(pass[i] != secr[i]) {
      good = SAFEBOOL_FALSE;
    }
  }
  if(good == SAFEBOOL_TRUE) {
    door = DOOR_OPEN;
  }
}
