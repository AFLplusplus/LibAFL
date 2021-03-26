#include <stdint.h>

#define STBI_ASSERT(x)
#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

int target_func(const uint8_t *buf, size_t size) {

  /*printf("BUF (%ld): ", size);
  for (int i = 0; i < size; i++) {
      printf("%02X", buf[i]);
  }
  printf("\n");*/
  
  if (size == 0) return 0;
  
  switch (buf[0]) {

    case 1:
      if (buf[1] == 0x44) {
        //__builtin_trap();
        return 8;
      }

      break;
    case 0xff:
      if (buf[2] == 0xff) {
        if (buf[1] == 0x44) {
          //*(char *)(0xdeadbeef) = 1;
          return 9;
        }
      }

      break;
    default:
      break;

  }

  return 1;

}
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{return target_func(data, size);
    int x, y, channels;

    if(!stbi_info_from_memory(data, size, &x, &y, &channels)) return 0;

    /* exit if the image is larger than ~80MB */
    if(y && x > (80000000 / 4) / y) return 0;

    unsigned char *img = stbi_load_from_memory(data, size, &x, &y, &channels, 4);

    free(img);

    return 0;
}
