#include "interop.h"
#include <stddef.h>
#include <stdint.h>

#define SYS_read 63
#define SYS_exit 93

extern uintptr_t syscall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2);
extern void printstr(const char* s);

static char INPUT_BUF[1 << 12];

int main(void) {
  for (int i = 0; i < sizeof(INPUT_BUF); i++) {
    INPUT_BUF[i] = 0;
  }
  printstr(ARIANE_READY);

  uint16_t size;
  syscall(SYS_read, 0, &size, sizeof(size));
  syscall(SYS_read, 0, INPUT_BUF, size);

  (*((void (*)()) INPUT_BUF))();

  syscall(SYS_exit, 0, 0, 0); // hard terminate execution

  return 0;
}