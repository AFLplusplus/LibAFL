#include <stdint.h>
#include <stdlib.h>
#include <string>

#ifdef _MSC_VER
  #include <windows.h>
  #include <winnt.h>
  #include <winternl.h>
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  (void)hModule;
  (void)lpReserved;
  (void)ul_reason_for_call;
  return TRUE;
}

  #define EXTERN extern "C" __declspec(dllexport)
#else
  #define EXTERN
extern "C" {
#endif

EXTERN int heap_uaf_read(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = new int[100];
  delete[] array;
  fprintf(stdout, "%d\n", array[5]);
  return 0;
}

EXTERN int heap_uaf_write(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = new int[100];
  delete[] array;
  array[5] = 1;
  return 0;
}

static volatile bool stop = false;

EXTERN int heap_oob_read(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;

  // while(!stop);

  // OutputDebugStringA("heap_oob_read\n");
  int *array = new int[100];
  fprintf(stdout, "%d\n", array[100]);
  delete[] array;
  return 0;
}

EXTERN int heap_oob_write(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = new int[100];
  array[100] = 1;
  delete[] array;
  return 0;
}
EXTERN int malloc_heap_uaf_read(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = static_cast<int *>(malloc(100 * sizeof(int)));
  free(array);
  fprintf(stdout, "%d\n", array[5]);
  return 0;
}

EXTERN int malloc_heap_uaf_write(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = static_cast<int *>(malloc(100 * sizeof(int)));
  free(array);
  array[5] = 1;
  return 0;
}

EXTERN int malloc_heap_oob_read(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = static_cast<int *>(malloc(100 * sizeof(int)));
  fprintf(stdout, "%d\n", array[100]);
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  int *array = static_cast<int *>(malloc(100 * sizeof(int)));
  array[100] = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x12(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x12));
  array[0x12] = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x14(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x14));
  array[0x14] = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x17(const uint8_t *_data, size_t _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x17));
  array[0x17] = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x17_int_at_0x16(const uint8_t *_data,
                                                  size_t         _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x17));
  *(int *)(&array[0x16]) = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x17_int_at_0x15(const uint8_t *_data,
                                                  size_t         _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x17));
  *(int *)(&array[0x15]) = 1;
  free(array);
  return 0;
}
EXTERN int malloc_heap_oob_write_0x17_int_at_0x14(const uint8_t *_data,
                                                  size_t         _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x17));
  *(int *)(&array[0x14]) = 1;
  free(array);
  return 0;
}

EXTERN int malloc_heap_oob_write_0x17_int_at_0x13(const uint8_t *_data,
                                                  size_t         _size) {
  (void)_data;
  (void)_size;
  char *array = static_cast<char *>(malloc(0x17));
  *(int *)(&array[0x13]) = 1;
  free(array);
  return 0;
}

EXTERN int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // abort();
  (void)data;
  (void)size;
  return 0;
}

#ifndef _MSC_VER
}
#endif
