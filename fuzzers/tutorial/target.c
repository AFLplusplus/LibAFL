#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define MAX_PACKET_SIZE 0x1000

typedef enum _packet_type {
  data_read = 0x0,
  data_write = 0x1,
  data_reset = 0x2,
} packet_type;

#pragma pack(1)
typedef struct _packet_data {
  packet_type type;
  uint64_t    offset;
  uint64_t    length;
  char        data[0];
} packet_data;

int LLVMFuzzerTestOneInput(const uint8_t *packet_buffer, size_t packet_length) {
  ssize_t      saved_data_length = 0;
  char        *saved_data = NULL;
  int          err = 0;
  packet_data *datagram = NULL;

  if (packet_length < sizeof(packet_data) || packet_length > MAX_PACKET_SIZE) {
    return 1;
  }

  datagram = (packet_data *)packet_buffer;

  switch (datagram->type) {
    case data_read:
      if (saved_data != NULL &&
          datagram->offset + datagram->length <= saved_data_length) {
        write(0, packet_buffer + datagram->offset, datagram->length);
      }
      break;

    case data_write:
      // NOTE: Who cares about checking the offset? Nobody would ever provide
      // bad data
      if (saved_data != NULL && datagram->length <= saved_data_length) {
        memcpy(saved_data + datagram->offset, datagram->data, datagram->length);
      }
      break;

    case data_reset:
      if (datagram->length > packet_length - sizeof(*datagram)) { return 1; }

      if (saved_data != NULL) { free(saved_data); }

      saved_data = malloc(datagram->length);
      saved_data_length = datagram->length;

      memcpy(saved_data, datagram->data, datagram->length);
      break;

    default:
      return 1;
  }

  return 0;
}
