#include "simplepass.h"
#define hw_balance(x) ((uint16_t)x | ((~(uint16_t)x)<<8))
#define honeypot(x)   ((((uint32_t)x) << 8) | (((uint32_t)x) << 16) | (((uint32_t)x) << 16))
volatile int door   = DOOR_CLOSED;
const char    secr[]       = "verysafe";
const uint8_t cmask[]      = "constmsk";
const uint8_t secr_cmask[] = {
  secr[0] ^ cmask[0],
  secr[1] ^ cmask[1],
  secr[2] ^ cmask[2],
  secr[3] ^ cmask[3],
  secr[4] ^ cmask[4],
  secr[5] ^ cmask[5],
  secr[6] ^ cmask[6],
  secr[7] ^ cmask[7],
  0
};
const uint16_t secr2[] = {
    hw_balance(secr[0]),
    hw_balance(secr[1]),
    hw_balance(secr[2]),
    hw_balance(secr[3]),
    hw_balance(secr[4]),
    hw_balance(secr[5]),
    hw_balance(secr[6]),
    hw_balance(secr[7]),
    hw_balance(secr[8])
};
const uint32_t secr3[] = {
    honeypot('f') | secr[0],
    honeypot('a') | secr[1],
    honeypot('k') | secr[2],
    honeypot('e') | secr[3],
    honeypot('p') | secr[4],
    honeypot('a') | secr[5],
    honeypot('s') | secr[6],
    honeypot('s') | secr[7],
    0,
};
uint16_t pass2[sizeof(secr)] = {0};
uint32_t pass3[sizeof(secr)] = {0};
const char   pstr[] = "Pass";
const char   fstr[] = "Fail";
uint8_t callback(uint8_t* pass, uint8_t len)
{
  for(int i=0;i<sizeof(secr);i++) {
    pass2[i] = hw_balance(pass[i]);
    pass3[i] = honeypot(pass[i])|pass[i];
  }
  trigger_high();
  validate(pass,pass2,pass3);
  trigger_low();
  simpleserial_put('r',sizeof(fstr),door==DOOR_OPEN?pstr:fstr);
  return 0;
}
void cyccnt_init()
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  //ETM->LAR = 0xC5ACCE55;
  ITM->LAR = 0xC5ACCE55;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
int main(void)
{
  platform_init();
  cyccnt_init();
  init_uart();
  trigger_setup();
  simpleserial_init();
  simpleserial_addcmd('p', sizeof(secr), callback);
  while(1)
  {
    simpleserial_get();
  }
}