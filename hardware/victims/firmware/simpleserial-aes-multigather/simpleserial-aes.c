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

#include "aes-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>

uint8_t get_mask(uint8_t* m, uint8_t len)
{
  aes_indep_mask(m, len);
  return 0x00;
}

uint8_t get_key(uint8_t* k, uint8_t len)
{
	aes_indep_key(k);
	return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    aes_indep_enc_pretrigger(pt);

	trigger_high();

  #ifdef ADD_JITTER
  for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
  #endif

	aes_indep_enc(pt); /* encrypting the data block */
	trigger_low();

    aes_indep_enc_posttrigger(pt);

	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
	return 0x00;
}

#define MAX_PLAINTEXT_QUEUE 128
uint8_t plaintext_queue[MAX_PLAINTEXT_QUEUE * 16];
uint8_t *plaintext_queue_next_put = plaintext_queue;
uint8_t *plaintext_queue_next_pop = plaintext_queue;
uint8_t * const plaintext_queue_end = plaintext_queue + (MAX_PLAINTEXT_QUEUE * 16);

uint8_t push_pt(uint8_t* pt, uint8_t len)
{
    if(plaintext_queue_next_put == plaintext_queue_end)
        return 0x01;
    memcpy(plaintext_queue_next_put, pt, 16);
    plaintext_queue_next_put += 16;
    return 0x00;
}

uint8_t process(uint8_t *_0, uint8_t _1)
{
    int count = (plaintext_queue_next_put - plaintext_queue) / 16;
    uint8_t* pt = plaintext_queue_next_pop;
    for(int i=0; i<count; ++i)
    {
        aes_indep_enc_pretrigger(pt);
	    trigger_high();
        #ifdef ADD_JITTER
        for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
        #endif
        aes_indep_enc(pt); /* encrypting the data block */
        trigger_low();
        aes_indep_enc_posttrigger(pt);
        pt += 16;
    }
    return 0x00;
}

uint8_t pop_pt(uint8_t *_0, uint8_t _1)
{
    if(plaintext_queue_next_pop == plaintext_queue_next_put)
        return 0x01;
    simpleserial_put('r', 16, plaintext_queue_next_pop);
    plaintext_queue_next_pop += 16;
    return 0x00;
}

uint8_t flush_pt(uint8_t *_0, uint8_t _1)
{
    plaintext_queue_next_put = plaintext_queue;
    plaintext_queue_next_pop = plaintext_queue;
    return 0x00;
}

int main(void)
{
	uint8_t tmp[KEY_LENGTH] = {DEFAULT_KEY};

    platform_init();
    init_uart();
    trigger_setup();

	aes_indep_init();
	aes_indep_key(tmp);

	simpleserial_init();
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    simpleserial_addcmd_flags('m', 18, get_mask, CMD_FLAG_LEN);
    simpleserial_addcmd('u', 16,  push_pt);
    simpleserial_addcmd('d',  0,  process);
    simpleserial_addcmd('o',  0,   pop_pt);
    simpleserial_addcmd('f',  0, flush_pt);
    while(1)
        simpleserial_get();
}
