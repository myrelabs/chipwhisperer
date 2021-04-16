#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void comb_init(void);
uint8_t select_comb_from_TCopy(uint8_t *pt);
uint8_t select_comb_from_TSource(uint8_t *pt);
uint8_t call_recode(uint8_t *pt);
uint8_t reseed(uint8_t *pt);


int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    comb_init();

    simpleserial_init();
    simpleserial_addcmd('t', 17, select_comb_from_TCopy);
    simpleserial_addcmd('a', 1, select_comb_from_TSource);
    simpleserial_addcmd('s', 33, call_recode);
    simpleserial_addcmd('r', 4, reseed);
    while(1)
        simpleserial_get();
}

