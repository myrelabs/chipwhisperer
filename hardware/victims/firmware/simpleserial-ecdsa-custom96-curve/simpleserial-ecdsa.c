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
uint8_t get_pbits_nbits(uint8_t *pt);

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    ecdsa_init();

    simpleserial_init();
    simpleserial_addcmd('k', 12, ecdsa_set_key);
    simpleserial_addcmd('g', 0, ecdsa_gen_key);
    simpleserial_addcmd('s', 13, ecdsa_gen_sig);
    simpleserial_addcmd('d', 13, ecdsa_gen_sig_det);
    simpleserial_addcmd('l', 0, get_pbits_nbits);
    while(1)
        simpleserial_get();
}

