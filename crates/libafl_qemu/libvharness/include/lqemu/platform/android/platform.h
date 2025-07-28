#ifndef PLATFORM_COMMON_H
#define PLATFORM_COMMON_H

#include "arch.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if LQEMU_WORD_SIZE == 64
typedef uint64_t lqword;
#elif LQEMU_WORD_SIZE == 32
typedef uint32_t lqword;
#endif

#define LQEMU_CALLING_CONVENTION

#define LQEMU_SUPPORT_STDIO

#endif
