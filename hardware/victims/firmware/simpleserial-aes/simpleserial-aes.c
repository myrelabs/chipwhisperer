#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
const char secr[] = "verysafe";
volatile int door = 0;
int check(char *p, char *q, int n) {
  for(int i=0;i<n;i++)
    if(p[i]!=q[i])
      return 0;
  return 1;
}
uint8_t run(uint8_t* p, uint8_t len) {
  trigger_high();
  if(check(p,secr,sizeof(secr)))
    door=1;
  trigger_low();
  simpleserial_put('r',5,door?"Pass":"Fail");
}
int main(void) {
  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();
  simpleserial_addcmd('p', sizeof(secr), run);
  while(1) {
    door=0;
    simpleserial_get();
  }
}

