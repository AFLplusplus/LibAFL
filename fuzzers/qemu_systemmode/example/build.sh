#!/bin/sh
arm-none-eabi-gcc -ggdb -ffreestanding -nostartfiles -lgcc -T mps2_m3.ld -mcpu=cortex-m3 main.c startup.c -o example.elf