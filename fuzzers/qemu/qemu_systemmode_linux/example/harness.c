// Adapted from
// https://github.com/google/fuzzing/blob/master/tutorial/libFuzzer/fuzz_me.cc
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <libafl_qemu.h>

bool FuzzMe(const uint8_t *Data, size_t DataSize) {
  return DataSize >= 3 && Data[0] == 'F' && Data[1] == 'U' && Data[2] == 'Z' &&
         Data[3] == 'Z';  // :‑<
}

int main() {
  // Prepare some space for the input
  uint8_t Data[10] = {0};

  // Start fuzzer here
  size_t len = LIBAFL_QEMU_START_VIRT((unsigned long)Data, 10);

  // Call the target
  bool ret = FuzzMe(Data, len);

  // Return to fuzzer
  if (ret) {
    // "Bug" has been triggered
    LIBAFL_QEMU_END(LIBAFL_QEMU_END_CRASH);
  } else {
    // Everything went well
    LIBAFL_QEMU_END(LIBAFL_QEMU_END_OK);
  }
}