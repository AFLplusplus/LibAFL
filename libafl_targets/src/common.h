#ifndef __LIBAFL_TARGETS_COMMON__
#define __LIBAFL_TARGETS_COMMON__

#include <stdint.h>

#ifdef _WIN32
  #define RETADDR (uintptr_t)_ReturnAddress()
  #define EXPORT_FN __declspec(dllexport)
#else
  #define RETADDR (uintptr_t)__builtin_return_address(0)
  #define EXPORT_FN
#endif

#ifdef __GNUC__
  #define MAX(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b;      \
                              \
    })
#else
  #define MAX(a, b) (((a) > (b)) ? (a) : (b)) 
#endif



#endif
