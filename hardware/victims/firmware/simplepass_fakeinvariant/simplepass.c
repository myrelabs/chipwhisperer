#include "simplepass.h"
void original(uint8_t* pass) {
  door = DOOR_CLOSED;
  for(int i=0;i<sizeof(secr);i++) {
    if(pass[i] != secr[i]) {
      return;
    }
  }
  door = DOOR_OPEN;
}
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3) {
  int clk_start = CLK_NOW;
  original(pass);
  while ((CLK_NOW - clk_start) < 150){}
}
