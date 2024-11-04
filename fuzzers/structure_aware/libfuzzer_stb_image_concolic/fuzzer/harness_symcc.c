#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>

// This is the same as harness.c. Instead of the LibFuzzer interface, this
// program simply has a main and takes the input file path as argument.

#define STBI_ASSERT(x)
#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

int main(int argc, char **argv) {
  if (argc < 2) { return -1; }

  char *file_path = argv[1];

  int x, y, channels;

  if (!stbi_info(file_path, &x, &y, &channels)) { return 0; }

  /* exit if the image is larger than ~80MB */
  if (y && x > (80000000 / 4) / y) { return 0; }

  unsigned char *img = stbi_load(file_path, &x, &y, &channels, 4);

  free(img);

  // if (x > 10000) {free(img);} // free crash

  return 0;
}
