#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



uint8_t qdsa_set_private_key(uint8_t *pt);
uint8_t qdsa_get_public_key(uint8_t *pt);

uint8_t qdsa_set_message(uint8_t *pt);
uint8_t qdsa_gen_sig(uint8_t *pt);
uint8_t qdsa_get_sig(uint8_t *pt);
uint8_t qdsa_ver_sig(uint8_t *pt);



int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();


    simpleserial_init();
    simpleserial_addcmd('k', 64, qdsa_set_private_key);
    simpleserial_addcmd('p', 0, qdsa_get_public_key);      //returns 32 octets
    simpleserial_addcmd('m', 33, qdsa_set_message);
    simpleserial_addcmd('s', 0, qdsa_gen_sig);
    simpleserial_addcmd('g', 0, qdsa_get_sig);         //returns 64 + message_length octets
    simpleserial_addcmd('v', 0, qdsa_ver_sig);         
    while(1)
        simpleserial_get();
}

