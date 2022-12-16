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
#define NOP9 NOP8; NOP8
#define NOPa NOP9; NOP9
#define NOPb NOPa; NOPa
#define NOPc NOPb; NOPb

int main(void) {
  // this is 2^12 c.nops
  NOPc;

  return 0;
}