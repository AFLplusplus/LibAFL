#include <sanitizer/allocator_interface.h>
#include <sanitizer/asan_interface.h>
#include <sanitizer/common_interface_defs.h>
#include <sanitizer/coverage_interface.h>
#include <sanitizer/dfsan_interface.h>
#include <sanitizer/hwasan_interface.h>
#include <sanitizer/lsan_interface.h>
#include <sanitizer/msan_interface.h>
#include <sanitizer/scudo_interface.h>
#include <sanitizer/tsan_interface_atomic.h>
#include <sanitizer/tsan_interface.h>
#include <sanitizer/ubsan_interface.h>

#if defined(__linux__)
  #include <sanitizer/linux_syscall_hooks.h>
#elif defined(__unix__) || !defined(__APPLE__) && defined(__MACH__)
  #include <sys/param.h>
  #if defined(BSD)
    #include <sanitizer/netbsd_syscall_hooks.h>
  #endif
#endif
