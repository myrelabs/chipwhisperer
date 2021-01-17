/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2016-2017 NewAE Technology Inc.

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

#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

//#define IDLE 0
//#define KEY 1
//#define PLAIN 2

uint8_t ecdsa_set_key(uint8_t *pt);

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Load all the keys etc */
    //ecdsa_init();

    simpleserial_init();
    simpleserial_addcmd('s', 32,  ecdsa_set_key);
    while(1)
        simpleserial_get();
}

