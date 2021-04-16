/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "salsa20.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

chacha_context_t ctx;

uint8_t set_key(uint8_t* k)
{
//     chacha_indep_key(k);
    chacha_setkey(&ctx, k);
    return 0x00;
}

uint8_t get_block(uint8_t* pt)
{
//     chacha_indep_enc_pretrigger(pt);
    
    trigger_high();

  #ifdef ADD_JITTER
  for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
  #endif

//     chacha_indep_enc(pt); /* encrypting the data block */
    uint64_t nonce, ctr;
    uint8_t out[64];
    memcpy(&nonce, pt,   8);
    memcpy(&ctr,   pt+8, 8);
    chacha_getblock(&ctx, nonce, ctr, out);
    trigger_low();
    
//     chacha_indep_enc_posttrigger(pt);
    
    simpleserial_put('r', 64, out);
    return 0x00;
}

uint8_t reset(uint8_t* x)
{
    // Reset key here if needed
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

//     chacha_indep_init();

    simpleserial_init();
    #if SS_VER == SS_VER_2_0
    #error "SS_VER_2_0 unimplemented"
    #else
    simpleserial_addcmd('k', 32, set_key);
    simpleserial_addcmd('p', 16, get_block);
    simpleserial_addcmd('x',  0, reset);
    #endif
    while(1)
        simpleserial_get();
}
