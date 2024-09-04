#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>

int shmid;

int set_shmid(int id) {
  shmid = id;
  return 0;
}

int set_value(int i) {
  void *res = shmat(shmid, NULL, 0);
  if ((int)res == -1) {
    printf("Failed to attach to memory with id=%d\n", shmid);
  } else {
    printf("pointer is %p\n", res);
  }
  uint8_t *array_ptr = (uint8_t *)res;
  array_ptr[i] = 1;
  return 0;
}

uint8_t get_value(int i) {
  void *res = shmat(shmid, NULL, 0);
  if ((int)res == -1) {
    printf("Failed to attach to memory with id=%d\n", shmid);
  }
  uint8_t *array_ptr = (uint8_t *)res;
  return array_ptr[i];
}

int destroy_shmem() {
  if (-1 == shmctl(shmid, IPC_RMID, NULL)) { return -1; }
  return 0;
}

void c_harness(char *array) {
  set_value(0);
  if (array[0] == 'a') {
    set_value(1);
    if (array[1] == 'b') {
      set_value(2);
      if (array[2] == 'a') {
        // abort 1
        // fprintf(stderr, "Will abort1\n");
        abort();
      }
      if (array[2] == 'b') {
        // abort 2
        // fprintf(stderr, "Will abort2\n");
        abort();
      }
      if (array[2] == 'c') {
        // abort 3
        // fprintf(stderr, "Will abort3\n");
        abort();
      }
    }
  }
}

int main(int argc, char *argv[]) {
  printf("running test_command\n");
  if (argc != 2) {
    printf("Need exactly two arguments\n");
    exit(-1);
  }
  int id = atoi(argv[1]);
  set_shmid(id);
  char buffer[100] = {0};
  read(STDIN_FILENO, buffer, 100);
  c_harness(buffer);
  printf("value[0]=%d\n", get_value(0));
  printf("value[1]=%d\n", get_value(1));
  printf("value[2]=%d\n", get_value(2));
  if (destroy_shmem() == -1) {
    printf("Failed to destroy the shared memory\n");
    exit(-1);
  }
  return 0;
}