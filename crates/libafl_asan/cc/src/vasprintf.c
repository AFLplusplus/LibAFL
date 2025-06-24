#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include "hooks.h"
#include "trace.h"

int vasprintf(char **restrict strp, const char *restrict fmt, va_list va) {
  trace("asprintf - strp: %p, fmt: %p\n", strp, fmt);
  if (strp == NULL) { return -1; }

  if (fmt == NULL) { return -1; }

  int len = vsnprintf(NULL, 0, fmt, va);

  if (len < 0) { return -1; }

  void *buffer = asan_alloc(len + 1, 0);
  if (buffer == NULL) { return -1; }

  *strp = buffer;
  return vsnprintf(buffer, len, fmt, va);
}
