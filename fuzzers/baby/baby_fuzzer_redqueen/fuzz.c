#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_U16 ((uint16_t)0xAABB)
#define MAGIC_U32 ((uint32_t)0x11223344)
#define MAGIC_U64 ((uint64_t)0x0102030405060708ULL)

static inline uint16_t load_u16(const uint8_t *p) {
  uint16_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static inline uint16_t bswap_u16(const uint16_t v) {
  return ((v & 0xff00) >> 8) | ((v & 0xff) << 8);
}

static inline uint32_t load_u32(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static inline uint32_t bswap_u32(const uint32_t v) {
  return ((v & 0xff000000UL) >> 24) | ((v & 0x00ff0000UL) >> 8) |
         ((v & 0x0000ff00UL) << 8) | ((v & 0x000000ffUL) << 24);
}

static inline uint64_t load_u64(const uint8_t *p) {
  uint64_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static inline uint64_t bswap_u64(const uint64_t v) {
  return ((v & 0xff00000000000000ULL) >> 56) |
         ((v & 0x00ff000000000000ULL) >> 40) |
         ((v & 0x0000ff0000000000ULL) >> 24) |
         ((v & 0x000000ff00000000ULL) >> 8) |
         ((v & 0x00000000ff000000ULL) << 8) |
         ((v & 0x0000000000ff0000ULL) << 24) |
         ((v & 0x000000000000ff00ULL) << 40) |
         ((v & 0x00000000000000ffULL) << 56);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 28) { return 0; }

  if (load_u16(data + 0) == MAGIC_U16) {
    if (bswap_u16(load_u16(data + 2)) == MAGIC_U16) {
      if (load_u32(data + 4) == MAGIC_U32) {
        if (bswap_u32(load_u32(data + 8)) == MAGIC_U32) {
          if (load_u64(data + 12) == MAGIC_U64) {
            if (bswap_u64(load_u64(data + 20)) == MAGIC_U64) { abort(); }
          }
        }
      }
    }
  }

  return 0;
}
