#include "hal.h"
#include "simpleserial.h"
#include "../unused-argument-util.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>



void ecdsa_init(void);
uint8_t ecdsa_set_key(uint8_t *pt, uint8_t UTILS_UNUSED_PARAM(len));
uint8_t ecdsa_gen_key(uint8_t* UTILS_UNUSED_PARAM(pt), uint8_t UTILS_UNUSED_PARAM(len));
uint8_t ecdsa_gen_sig(uint8_t *pt, uint8_t len);
uint8_t ecdsa_gen_sig_det(uint8_t *pt, uint8_t len);
uint8_t get_pbits_nbits(uint8_t* UTILS_UNUSED_PARAM(pt), uint8_t UTILS_UNUSED_PARAM(len));

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    ecdsa_init();

    simpleserial_init();
    simpleserial_addcmd('k', 12, ecdsa_set_key);
    simpleserial_addcmd('g', 0, ecdsa_gen_key);
    simpleserial_addcmd_flags('s', 0xFF, ecdsa_gen_sig, CMD_FLAG_LEN);    //0xFF to stress up that the length of the input indicated by the second argument of the added function
    simpleserial_addcmd_flags('d', 0xFF, ecdsa_gen_sig_det, CMD_FLAG_LEN);
    simpleserial_addcmd('l', 0, get_pbits_nbits);
    while(1)
        simpleserial_get();
}

