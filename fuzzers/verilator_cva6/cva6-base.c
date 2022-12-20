#include <stdint.h>

#define NOP0 asm volatile ( "ADDI x0, x0, 0" )
#define NOP1 NOP0; NOP0
#define NOP2 NOP1; NOP1
#define NOP3 NOP2; NOP2
#define NOP3 NOP2; NOP2
#define NOP4 NOP3; NOP3
#define NOP5 NOP4; NOP4
#define NOP6 NOP5; NOP5
#define NOP7 NOP6; NOP6
#define NOP8 NOP7; NOP7

#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93

extern uintptr_t syscall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2);
extern void printstr(const char* s);

static volatile char INPUT_BUF[1 << 12] __attribute__((aligned(64))) = { 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 0 };

int main(void) {
  NOP8; // enough nop's to get noticed via printing
  __sync_synchronize(); // flush all buffers; we have sideloaded input

  (*((void (*)()) INPUT_BUF))();

  return 0;
}