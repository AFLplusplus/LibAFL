#include <limits.h>
#include <stdarg.h>
#include <stdio.h>

static char log_buffer[PATH_MAX] = {0};

extern void log_trace(char *msg);

void trace(const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  int len = vsnprintf(log_buffer, sizeof(log_buffer), fmt, va);
  if (len > 0) { log_trace(log_buffer); }
  va_end(va);
}
