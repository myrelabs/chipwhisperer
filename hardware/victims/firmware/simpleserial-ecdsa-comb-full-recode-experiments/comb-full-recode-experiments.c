#include "hal.h"
#include "simpleserial.h"
#include "../unused-argument-util.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void comb_recode_init(void);
uint8_t call_recode(uint8_t *pt, uint8_t UTILS_UNUSED_PARAM(len));


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

