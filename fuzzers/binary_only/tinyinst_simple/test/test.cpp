/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

// shared memory stuff
#if defined(__linux__)
  #include <sys/shm.h>
#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  #include <windows.h>
#else
  #include <sys/mman.h>
#endif

#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

bool use_shared_memory;

#if defined(__linux__)

int setup_shmem(const char *name) {
  // map shared memory to process address space
  shm_data = (unsigned char *)shmat(atoi(name), NULL, 0);
  if (shm_data == (void *)-1) {
    perror("Error in shmat");
    return 0;
  }
  return 1;
}

#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32)

int setup_shmem(const char *name) {
  HANDLE map_file;

  map_file = OpenFileMapping(FILE_MAP_ALL_ACCESS,  // read/write access
                             FALSE,                // do not inherit the name
                             name);                // name of mapping object

  if (map_file == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  shm_data = (unsigned char *)MapViewOfFile(
      map_file,             // handle to map object
      FILE_MAP_ALL_ACCESS,  // read/write permission
      0, 0, SHM_SIZE);

  if (shm_data == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  return 1;
}

#else

int setup_shmem(const char *name) {
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    perror("Error in shm_open");
    return 0;
  }

  // map shared memory to process address space
  shm_data =
      (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED) {
    perror("Error in mmap");
    return 0;
  }

  return 1;
}

#endif

// used to force a crash
char *crash = NULL;

// ensure we can find the target

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  #define FUZZ_TARGET_MODIFIERS __declspec(dllexport)
#else
  #define FUZZ_TARGET_MODIFIERS __attribute__((noinline))
#endif

// actual target function

// Use extern "C" to preserve the function name for instrumentation
#ifdef __cplusplus
extern "C"
#endif  // __cplusplus
    void FUZZ_TARGET_MODIFIERS
    fuzz(char *name) {
  char    *sample_bytes = NULL;
  uint32_t sample_size = 0;

  // read the sample either from file or
  // shared memory
  if (use_shared_memory) {
    sample_size = *(uint32_t *)(shm_data);
    if (sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
    sample_bytes = (char *)malloc(sample_size);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
  } else {
    FILE *fp = fopen(name, "rb");
    if (!fp) {
      printf("Error opening %s a\n", name);
      return;
    }
    fseek(fp, 0, SEEK_END);
    sample_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    sample_bytes = (char *)malloc(sample_size);
    fread(sample_bytes, 1, sample_size, fp);
    fclose(fp);
  }
  // printf("sample_bytes: %s", sample_bytes);
  if (sample_size >= 4) {
    // check if the sample spells "test"
    if (*(uint32_t *)(sample_bytes) == 0x74736574) {
      // if so, crash
      crash[0] = 1;
    }
  }

  if (sample_bytes) free(sample_bytes);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }
  if (!strcmp(argv[1], "-m")) {
    use_shared_memory = true;
  } else if (!strcmp(argv[1], "-f")) {
    use_shared_memory = false;
  } else {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }

  // map shared memory here as we don't want to do it
  // for every operation
  if (use_shared_memory) {
    if (!setup_shmem(argv[2])) { printf("Error mapping shared memory\n"); }
  }

  fuzz(argv[2]);

  return 0;
}
