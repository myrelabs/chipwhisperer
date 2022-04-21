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

//#include "aes-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include <string.h>
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

#define MAX_PLAINTEXT_QUEUE 16
uint8_t plaintext_queue[MAX_PLAINTEXT_QUEUE * 16];
uint8_t *plaintext_queue_next_put = plaintext_queue;
uint8_t *plaintext_queue_next_pop = plaintext_queue;
uint8_t * const plaintext_queue_end = plaintext_queue + (MAX_PLAINTEXT_QUEUE * 16);

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
    /* Uncomment this for manual clock setup */

    /*
    RCC_ClkInitTypeDef RCC_ClkInitStruct;
	RCC_ClkInitStruct.ClockType      = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
	RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_HSE;
	RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV8;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
	uint32_t flash_latency = 5;
	HAL_RCC_ClockConfig(&RCC_ClkInitStruct, flash_latency);
    */

    __HAL_RCC_CRYP_CLK_ENABLE();

    /* Set the key size and data type*/
    CRYP->CR = (uint32_t) (CRYP_KEYSIZE_128B | CRYP_DATATYPE_8B);

    set_key(hw_key);

    CRYP->CR |= CRYP_CR_ALGOMODE_AES_ECB;
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

void crypt_many(uint8_t *buffer, int count)
{
    uint8_t *inputaddr = buffer;
    uint8_t *outputaddr = buffer;

    CRYP->CR |= CRYP_CR_FFLUSH;

    const uint32_t CR = CRYP->CR;
    const uint32_t CR_en = CR | CRYP_CR_CRYPEN;
    const uint32_t CR_di = CR & ~CRYP_CR_CRYPEN;
    
    for(int i=0; i<count; ++i)
    {
        /* Write the Input block in the IN FIFO */
        CRYP->DR = *(uint32_t*)(inputaddr);
        inputaddr+=4U;
        CRYP->DR = *(uint32_t*)(inputaddr);
        inputaddr+=4U;
        CRYP->DR = *(uint32_t*)(inputaddr);
        inputaddr+=4U;
        CRYP->DR = *(uint32_t*)(inputaddr);
        inputaddr+=4U;

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
}

uint8_t get_mask(uint8_t* m, uint8_t len)
{
    //aes_indep_mask(m);
    return 0x00;
}

uint8_t get_key(uint8_t* k, uint8_t len)
{
	set_key(k);
	return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
	//trigger_high();
	crypt(pt); /* encrypting the data block */
	//trigger_low();
	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
	return 0x00;
}

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
    crypt_many(plaintext_queue, (plaintext_queue_next_put - plaintext_queue) / 16);
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
    platform_init();
    init_uart();
    trigger_setup();

	init();

    /* Uncomment this to get a HELLO message for debug */

    /*
    putch('h');
    putch('e');
    putch('l');
    putch('l');
    putch('o');
    putch('\n');
    */

	simpleserial_init();
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    simpleserial_addcmd('m', 18, get_mask);
    simpleserial_addcmd('u', 16, push_pt);
    simpleserial_addcmd('d',  0, process);
    simpleserial_addcmd('o',  0,  pop_pt);
    simpleserial_addcmd('f',  0,flush_pt);
    while(1)
        simpleserial_get();
}
