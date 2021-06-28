#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void comb_recode_init(void);
uint8_t call_recode(uint8_t *pt);


int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    comb_recode_init();

    simpleserial_init();
    simpleserial_addcmd('s', 34, call_recode);
    while(1)
        simpleserial_get();
}

