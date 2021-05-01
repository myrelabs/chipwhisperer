#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void comb_init(void);
uint8_t select_comb(uint8_t *pt);
uint8_t select_comb_no_output(uint8_t *pt);
uint8_t call_recode(uint8_t *pt);

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    comb_init();

    simpleserial_init();
    simpleserial_addcmd('s', 2, select_comb);
    simpleserial_addcmd('n', 2, select_comb_no_output);
    simpleserial_addcmd('r', 33, call_recode);
    while(1)
        simpleserial_get();
}

