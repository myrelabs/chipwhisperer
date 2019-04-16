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

#include "mt.h"

//#include "aes-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>

#include <stm32f2_hal.h>
#include <stm32f2_hal_lowlevel.h>
#include <stm32f2xx_hal_rcc.h>
#include <stm32f2xx_hal_gpio.h>
#include <stm32f2xx_hal_dma.h>
// #include <stm32f2xx_hal_uart.h>
#include <stm32f2xx_hal_cryp.h>

/* stm32f2_hal.c */
extern uint8_t hw_key[16];

void set_key(uint8_t *keyaddr)
{
    CRYP->K2LR = __REV(*(uint32_t*)(keyaddr));
    keyaddr+=4U;
    CRYP->K2RR = __REV(*(uint32_t*)(keyaddr));
    keyaddr+=4U;
    CRYP->K3LR = __REV(*(uint32_t*)(keyaddr));
    keyaddr+=4U;
    CRYP->K3RR = __REV(*(uint32_t*)(keyaddr));
}


void init(void)
{
    RCC_ClkInitTypeDef RCC_ClkInitStruct;
	RCC_ClkInitStruct.ClockType      = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
	RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_HSE;
	RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV8;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
	uint32_t flash_latency = 5;
	HAL_RCC_ClockConfig(&RCC_ClkInitStruct, flash_latency);

    __HAL_RCC_CRYP_CLK_ENABLE();

    /* Set the key size and data type*/
    CRYP->CR = (uint32_t) (CRYP_KEYSIZE_128B | CRYP_DATATYPE_8B);

    set_key(hw_key);

    CRYP->CR |= CRYP_CR_ALGOMODE_AES_ECB;
}

void seed_rng(uint8_t *buf)
{
    // 
}

void crypt(uint8_t *buffer)
{
    uint8_t *inputaddr = buffer;
    uint8_t *outputaddr = buffer;

    CRYP->CR |= CRYP_CR_FFLUSH;

    /* Write the Input block in the IN FIFO */
    CRYP->DR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    CRYP->DR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    CRYP->DR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    CRYP->DR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;

    const uint32_t CR = CRYP->CR;
    const uint32_t CR_en = CR | CRYP_CR_CRYPEN;
    const uint32_t CR_di = CR & ~CRYP_CR_CRYPEN;
    
    /* TRIGGER HIGH */
    GPIOA->BSRR = GPIO_PIN_12;

    /* Enable CRYP */
    CRYP->CR = CR_en;

    while(HAL_IS_BIT_CLR(CRYP->SR, CRYP_FLAG_OFNE))
    {    
    }

    /* TRIGGER LOW */
    GPIOA->BSRR = (GPIO_PIN_12 << 16);

    /* Read the Output block from the Output FIFO */
    *(uint32_t*)(outputaddr) = CRYP->DOUT;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = CRYP->DOUT;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = CRYP->DOUT;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = CRYP->DOUT;
    outputaddr+=4U;

    /* Disable CRYP */
    CRYP->CR = CR_di;
}

void crypt_twice(uint8_t* buffer)
{
    uint32_t *inputaddr = (uint32_t*)buffer;
    uint32_t *outputaddr = (uint32_t*)buffer;

    CRYP->CR |= CRYP_CR_FFLUSH;

    /* Write the Input block in the IN FIFO */
    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);

    /* ... twice */
    inputaddr = (uint32_t*)buffer;

    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);
    CRYP->DR = *(inputaddr++);

    const uint32_t CR = CRYP->CR;
    const uint32_t CR_en = CR | CRYP_CR_CRYPEN;
    const uint32_t CR_di = CR & ~CRYP_CR_CRYPEN;
    
    /* TRIGGER HIGH */
    GPIOA->BSRR = GPIO_PIN_12;

    /* Enable CRYP */
    CRYP->CR = CR_en;

    while(HAL_IS_BIT_CLR(CRYP->SR, CRYP_FLAG_OFNE))
    {    
    }

    /* TRIGGER LOW */
    GPIOA->BSRR = (GPIO_PIN_12 << 16);

    /* Read the Output block from the Output FIFO */
    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;

    /* ... twice */
    outputaddr = (uint32_t*)buffer;

    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;
    *(outputaddr++) = CRYP->DOUT;

    /* Disable CRYP */
    CRYP->CR = CR_di;
}

uint8_t get_mask(uint8_t* m)
{
    //aes_indep_mask(m);
    return 0x00;
}

uint8_t get_key(uint8_t* k)
{
	set_key(k);
	return 0x00;
}

uint8_t get_pt(uint8_t* pt)
{
	//trigger_high();
	crypt_twice(pt); /* encrypting the data block */
	//trigger_low();
	simpleserial_put('r', 16, pt);
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

	init();

    /* Uncomment this to get a HELLO message for debug */

    putch('h');
    putch('e');
    putch('l');
    putch('l');
    putch('o');
    putch('\n');

	simpleserial_init();
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    simpleserial_addcmd('m', 18, get_mask);
    while(1)
        simpleserial_get();
}
