#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// This wraps harness.c into an executable program that reads it's input from
// stdin.

#define STBI_ASSERT(x)
#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

int main() {
  int x, y, channels;

  if (!stbi_load_from_file(stdin, &x, &y, &channels, 4))
    return 0;

  /* exit if the image is larger than ~80MB */
  if (y && x > (80000000 / 4) / y)
    return 0;

  // if (x > 10000) free(img); // free crash

  return 0;

  return 0;
}
