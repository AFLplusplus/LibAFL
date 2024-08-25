// Adapted from
// https://github.com/google/fuzzing/blob/master/tutorial/libFuzzer/fuzz_me.cc
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include <libafl_qemu.h>

bool FuzzMe(const uint8_t *Data, size_t DataSize) {
  if (DataSize > 3) {
    if (Data[0] == 'F') {
      if (Data[1] == 'U') {
        if (Data[2] == 'Z') {
          if (Data[3] == 'Z') { return true; }
        }
      }
    }
  }

  return false;
}

int main() {
  // Prepare some space for the input
  uint8_t Data[10] = {0};

  lqprintf("Fuzzing starts\n");

  // Start fuzzer here
  size_t len = libafl_qemu_start_virt(Data, 10);

  // Call the target
  bool ret = FuzzMe(Data, len);

  // Return to fuzzer
  if (ret) {
    // "Bug" has been triggered
    libafl_qemu_end(LIBAFL_QEMU_END_CRASH);
  } else {
    // Everything went well
    libafl_qemu_end(LIBAFL_QEMU_END_OK);
  }
}