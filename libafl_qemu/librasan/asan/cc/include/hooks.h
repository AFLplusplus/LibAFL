#include <stddef.h>

void   asan_load(const void *addr, size_t size);
void   asan_store(const void *addr, size_t size);
void  *asan_alloc(size_t len, size_t align);
void   asan_dealloc(const void *addr);
size_t asan_get_size(const void *addr);
size_t asan_sym(const char *name);
size_t asan_page_size();
