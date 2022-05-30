#include <stdint.h>
#include <assert.h>

#define STBI_ASSERT(x)
#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int x, y, channels;

  if (!stbi_info_from_memory(data, size, &x, &y, &channels)) { return 0; }

  /* exit if the image is larger than ~80MB */
  if (y && x > (80000000 / 4) / y) { return 0; }

  unsigned char *img = stbi_load_from_memory(data, size, &x, &y, &channels, 4);

  free(img);

  // if (x > 10000) free(img); // free crash

  // if (x > 10000) {free(img);} // free crash

  return 0;
}
