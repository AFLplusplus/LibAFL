/*
 * FreeRTOS V202112.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

typedef unsigned int uint32_t;

extern int main();

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;

/* Prevent optimization so gcc does not replace code with memcpy */
__attribute__((optimize("O0"))) __attribute__((naked)) void Reset_Handler(
    void) {
  /* set stack pointer */
  __asm volatile("ldr r0, =_estack");
  __asm volatile("mov sp, r0");

  /* copy .data section from flash to RAM */
  // Not needed for this example, see linker script
  // for( uint32_t * src = &_sidata, * dest = &_sdata; dest < &_edata; )
  // {
  //     *dest++ = *src++;
  // }

  /* zero out .bss section */
  for (uint32_t *dest = &_sbss; dest < &_ebss;) {
    *dest++ = 0;
  }

  /* jump to board initialisation */
  void _start(void);
  _start();
}

const uint32_t *isr_vector[] __attribute__((section(".isr_vector"))) = {
    (uint32_t *)&_estack,
    (uint32_t *)&Reset_Handler, /* Reset                -15 */
    0,                          /* NMI_Handler          -14 */
    0,                          /* HardFault_Handler    -13 */
    0,                          /* MemManage_Handler    -12 */
    0,                          /* BusFault_Handler     -11 */
    0,                          /* UsageFault_Handler   -10 */
    0,                          /* reserved */
    0,                          /* reserved */
    0,                          /* reserved */
    0,                          /* reserved   -6 */
    0,                          /* SVC_Handler              -5 */
    0,                          /* DebugMon_Handler         -4 */
    0,                          /* reserved */
    0,                          /* PendSV handler    -2 */
    0,                          /* SysTick_Handler   -1 */
    0,                          /* uart0 receive 0 */
    0,                          /* uart0 transmit */
    0,                          /* uart1 receive */
    0,                          /* uart1 transmit */
    0,                          /* uart 2 receive */
    0,                          /* uart 2 transmit */
    0,                          /* GPIO 0 combined interrupt */
    0,                          /* GPIO 2 combined interrupt */
    0,                          /* Timer 0 */
    0,                          /* Timer 1 */
    0,                          /* Dial Timer */
    0,                          /* SPI0 SPI1 */
    0,                          /* uart overflow 1, 2,3 */
    0,                          /* Ethernet   13 */
};

__attribute__((naked)) void exit(__attribute__((unused)) int status) {
  /* Force qemu to exit using ARM Semihosting */
  __asm volatile(
      "mov r1, r0\n"
      "cmp r1, #0\n"
      "bne .notclean\n"
      "ldr r1, =0x20026\n" /* ADP_Stopped_ApplicationExit, a clean exit */
      ".notclean:\n"
      "movs r0, #0x18\n" /* SYS_EXIT */
      "bkpt 0xab\n"
      "end: b end\n");
}

void _start(void) {
  main();
  exit(0);
}
