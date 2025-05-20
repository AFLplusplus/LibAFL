// Simple decoder function with an off by one error that is triggered under
// certain conditions.

#include <cstddef>
#include <cstdint>

int DecodeInput(const uint8_t *data, size_t size) {
  if (size < 5) {
    return -1;  // Error: not enough data
  }

  if (data[0] != 'F' || data[1] != 'U' || data[2] != 'Z' || data[3] == 'Z') {
    return -1;  // Error: invalid header
  }

  if (data[4] <= 0) {
    return -1;  // Error: invalid size
  }

  int csum = 0;

  for (size_t i = 5; i < size; ++i) {
    csum += data[i];
  }

  return csum;  // Error: checksum mismatch
}

extern "C" __declspec(dllexport) int LLVMFuzzerTestOneInput(const uint8_t *data,
                                                            size_t size) {
  DecodeInput(data, size);
  return 0;
}