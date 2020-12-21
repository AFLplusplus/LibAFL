/* An in mmeory fuzzing example. Fuzzer for libpng library */

#include <stdio.h>
#include <stdint.h>

#include "png.h"

/* The actual harness. Using PNG for our example. */
int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {

  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

  png_set_user_limits(png_ptr, 65535, 65535);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

  if (setjmp(png_jmpbuf(png_ptr))) return 0;

  png_set_progressive_read_fn(png_ptr, NULL, NULL, NULL, NULL);
  png_process_data(png_ptr, info_ptr, (uint8_t *)input, len);

  return 0;

}