#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void ecdsa_init(void);
uint8_t ecdsa_set_key(uint8_t *pt);
uint8_t ecdsa_gen_key(uint8_t *pt);
uint8_t ecdsa_gen_sig(uint8_t *pt);
uint8_t ecdsa_gen_sig_det(uint8_t *pt);

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    ecdsa_init();

    simpleserial_init();
    simpleserial_addcmd('k', 32, ecdsa_set_key);
    simpleserial_addcmd('g', 0, ecdsa_gen_key);
    simpleserial_addcmd('s', 33, ecdsa_gen_sig);
    simpleserial_addcmd('d', 33, ecdsa_gen_sig_det);
    while(1)
        simpleserial_get();
}

