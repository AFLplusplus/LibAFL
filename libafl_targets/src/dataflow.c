#include "dataflow.h"

#include "common.h"
#include <stdlib.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size);

EXPORT_FN int libafl_dataflow_test_one_input(const uint8_t *data, size_t len) {
  uint8_t *buf = malloc(len);
  memcpy(buf, data, len);
  dfsan_set_label(1, buf, len);

  int res = LLVMFuzzerTestOneInput(buf, len);
  free(buf);

  return res;
}

EXPORT_FN int libafl_dataflow_test_one_input_with_labels(const uint8_t *data, size_t len, const uint8_t *labels) {
  uint8_t *buf = malloc(len);
  memcpy(buf, data, len);
  for (size_t i = 0; i < len; i++) {
    dfsan_set_label(labels[i], buf + i, 1);
  }

  int res = LLVMFuzzerTestOneInput(buf, len);
  free(buf);

  return res;
}

EXT_FUNC_IMPL(libafl_main, void, (void), false) {
}

EXT_FUNC_IMPL(main, int, (int argc, char** argv), false) {
  libafl_main();
  return 0;
}