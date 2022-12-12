#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

#define MAX_INPUT_SIZE 3
#define SHMEM_COUNT 100
int   shmid;
key_t key = 58974;

int create_shmem_array() {
  shmid = shmget(key, SHMEM_COUNT * sizeof(uint8_t), IPC_CREAT | 0666);
  printf("created a shared memory segment with shmid=%d\n", shmid);
  void    *res = shmat(shmid, NULL, 0);
  uint8_t *array_ptr = (uint8_t *)res;
  for (int i = 0; i < SHMEM_COUNT; i++) {
    array_ptr[i] = 0;
  }
  return 0;
}

int set_value(int i) {
  void    *res = shmat(shmid, NULL, 0);
  uint8_t *array_ptr = (uint8_t *)res;
  array_ptr[i] = 1;
  return 0;
}

uint8_t get_value(int i) {
  void    *res = shmat(shmid, NULL, 0);
  uint8_t *array_ptr = (uint8_t *)res;
  return array_ptr[i];
}

int destroy_shmem(int id) {
  if (-1 == shmctl(id, IPC_RMID, NULL)) { return -1; }
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

uint8_t *get_ptr() {
  void *res = shmat(shmid, NULL, 0);
  return (uint8_t *)res;
}

// To remove
// int main() {
//   create_shmem_array();
//   uint8_t input[MAX_INPUT_SIZE] = {0};
//   input[0] = 97;
//   input[1] = 98;
//   input[2] = 92;
//   c_harness(&input);
//   printf("%d", get_value(0));
//   printf("%d", get_value(1));
//   printf("%d", get_value(2));
//   printf("%d", get_value(3));
//   destroy_shmem(shmid);
//   return 0;
// }