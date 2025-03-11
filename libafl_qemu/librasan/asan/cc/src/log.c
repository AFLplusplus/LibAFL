#include <limits.h>
#include <stdarg.h>
#include "printf.h"

static char log_buffer[PATH_MAX] = {0};

extern void log_trace(char *msg);

void trace(const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  int len = vsnprintf_(log_buffer, sizeof(log_buffer), fmt, va);
  if (len > 0) { log_trace(log_buffer); }
  va_end(va);
}

#ifdef __powerpc__
void _putchar(char c) {
  (void)c;
}
#endif
