#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

#define MAX_INPUT_SIZE 3
#define MAP_SIZE 100

// uint8_t *array;
uint8_t  array[MAP_SIZE];
uint8_t *array_ptr = &array;

int init() {
  for (int i = 0; i < MAP_SIZE; i++) {
    array[i] = 0;
  }
  return 0;
}

int set_value(int i) {
  array[i] = 1;
  return 0;
}

void c_harness(uint8_t *array) {
  set_value(0);
  if (array[0] == 'a') {
    set_value(1);
    if (array[1] == 'b') {
      set_value(2);
      if (array[2] == 'a') {
        // abort 1
        abort();
      }
      if (array[2] == 'b') {
        // abort 2
        abort();
      }
      if (array[2] == 'c') {
        // abort 3
        abort();
      }
    }
  }
}