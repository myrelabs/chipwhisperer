#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void comb_scalar_mult_init(void);
uint8_t call_recode(uint8_t *pt);
uint8_t ecdsa_set_key(uint8_t *pt);
uint8_t reseed(uint8_t *pt);


int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    comb_scalar_mult_init();

    simpleserial_init();
    simpleserial_addcmd('s', 33, call_recode);
    simpleserial_addcmd('k', 32, ecdsa_set_key);    
    simpleserial_addcmd('r', 4, reseed);
    while(1)
        simpleserial_get();
}

