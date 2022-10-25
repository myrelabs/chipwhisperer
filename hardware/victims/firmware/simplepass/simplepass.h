#ifndef __SIMPLEPASS_H__
#define __SIMPLEPASS_H__
#include "hal.h"
#if HAL_TYPE == HAL_stm32f3
#include "stm32f303x8.h"
#include "core_cm4.h"
#endif
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#define CLK_NOW     DWT->CYCCNT
#define DOOR_OPEN   0xA5
#define DOOR_CLOSED 0x5A
extern volatile int      door;
extern const    char     secr[9];
extern const    uint16_t secr2[];
extern const    uint32_t secr3[];
extern          uint16_t pass2[];
extern          uint32_t pass3[];
extern const    uint8_t  cmask[];
extern const    uint8_t  secr_cmask[];
extern          uint8_t  vmask[];
extern          uint8_t  secr_vmask[];
void validate(uint8_t* pass, uint16_t* pass2, uint32_t* pass3);
#endif
