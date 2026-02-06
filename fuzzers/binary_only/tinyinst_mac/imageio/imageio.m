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

#include <Foundation/Foundation.h>
#include <Foundation/NSURL.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/shm.h>
#include <dirent.h>
#include <sys/resource.h>

#import <ImageIO/ImageIO.h>
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>

// shared memory stuff

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

bool use_shared_memory;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)

int setup_shmem(const char* name) {
  HANDLE map_file;

  map_file = OpenFileMapping(
    FILE_MAP_ALL_ACCESS,   // read/write access
    FALSE,                 // do not inherit the name
    name);            // name of mapping object

  if (map_file == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  shm_data = (unsigned char*)MapViewOfFile(map_file, // handle to map object
    FILE_MAP_ALL_ACCESS,  // read/write permission
    0,
    0,
    SHM_SIZE);

  if (shm_data == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  return 1;
}

#else

int setup_shmem(const char *name)
{
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1)
  {
    printf("Error in shm_open\n");
    return 0;
  }

  // map shared memory to process address space
  shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED)
  {
    printf("Error in mmap\n");
    return 0;
  }

  return 1;
}

#endif

// ensure we can find the target

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#define FUZZ_TARGET_MODIFIERS __declspec(dllexport)
#else
#define FUZZ_TARGET_MODIFIERS __attribute__ ((noinline))
#endif

// actual target function

extern bool CGRenderingStateGetAllowsAcceleration(void*);
extern bool CGRenderingStateSetAllowsAcceleration(void*, bool);
extern void* CGContextGetRenderingState(CGContextRef);

void dummyLogProc() { }

extern void ImageIOSetLoggingProc(void*);

CGContextRef ctx;

void FUZZ_TARGET_MODIFIERS fuzz(char *name) {
  NSImage* img = NULL;
  char *sample_bytes = NULL;
  uint32_t sample_size = 0;

  if(use_shared_memory) {
    sample_size = *(uint32_t *)(shm_data);
    if(sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
    sample_bytes = (char *)malloc(sample_size);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
    img = [[NSImage alloc] initWithData:[NSData dataWithBytes:sample_bytes length:sample_size]];
  } else {
    img = [[NSImage alloc] initWithContentsOfFile:[NSString stringWithUTF8String:name]];
  }
  
  CGImageRef cgImg = [img CGImageForProposedRect:nil context:nil hints:nil];
  if (cgImg) {
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    // printf("Width: %lu, height: %lu\n", width, height);
    CGRect rect = CGRectMake(0, 0, width, height);
    CGContextDrawImage(ctx, rect, cgImg);
    CGImageRelease(cgImg);
  }

  if(sample_bytes) free(sample_bytes);
}

int main(int argc, char **argv)
{
  if(argc != 3) {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }
  
  if(!strcmp(argv[1], "-m")) {
    use_shared_memory = true;
  } else if(!strcmp(argv[1], "-f")) {
    use_shared_memory = false;
  } else {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }

  // map shared memory here as we don't want to do it
  // for every operation
  if(use_shared_memory) {
    if(!setup_shmem(argv[2])) {
      printf("Error mapping shared memory\n");
    }
  }

  ImageIOSetLoggingProc(&dummyLogProc);
  CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();
  ctx = CGBitmapContextCreate(0, 32, 32, 8, 0, colorspace, 1);
  void* renderingState = CGContextGetRenderingState(ctx);
  CGRenderingStateSetAllowsAcceleration(renderingState, false);
  
  fuzz(argv[2]);
  
  return 0;
}
