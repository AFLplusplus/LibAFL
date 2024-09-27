#ifdef TARGET_SYNC_EXIT
  #include "libafl_qemu.h"
#endif

#ifndef TARGET_SYNC_EXIT
int __attribute__((noinline)) BREAKPOINT() {
  for (;;) {}
}
#endif

int LLVMFuzzerTestOneInput(unsigned int *Data, unsigned int Size) {
#ifdef TARGET_SYNC_EXIT
  libafl_qemu_start_phys((void *)Data, Size);
#endif
  if (Data[3] == 0) {
    while (1) {}
  }  // cause a timeout
  for (int i = 0; i < Size; i++) {
    // if (Data[i] > 0xFFd0 && Data[i] < 0xFFFF) {return 1;}    // cause qemu to
    // crash
    for (int j = i + 1; j < Size; j++) {
      if (Data[j] == 0) { continue; }
      if (Data[j] > Data[i]) {
        int tmp = Data[i];
        Data[i] = Data[j];
        Data[j] = tmp;
        if (Data[i] <= 100) { j--; }
      }
    }
  }
#ifdef TARGET_SYNC_EXIT
  libafl_qemu_end(LIBAFL_QEMU_END_OK);
#else
  return BREAKPOINT();
#endif
}
unsigned int FUZZ_INPUT[] = {
    101, 201, 700, 230, 860, 234, 980, 200, 340, 678, 230, 134, 900,
    236, 900, 123, 800, 123, 658, 607, 246, 804, 567, 568, 207, 407,
    246, 678, 457, 892, 834, 456, 878, 246, 699, 854, 234, 844, 290,
    125, 324, 560, 852, 928, 910, 790, 853, 345, 234, 586,
};

int main() {
  LLVMFuzzerTestOneInput(FUZZ_INPUT, 50);
}
