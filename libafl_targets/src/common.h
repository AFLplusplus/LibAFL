#ifndef __LIBAFL_TARGETS_COMMON__
#define __LIBAFL_TARGETS_COMMON__

#include <stdint.h>

#define true 1
#define false 0

#define STATIC_ASSERT(pred) switch(0){case 0:case pred:;}

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
  #define MIN(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a < _b ? _a : _b;      \
                              \
    })
  #define MEMCPY __builtin_memcpy
#else
  #define MAX(a, b) (((a) > (b)) ? (a) : (b)) 
  #define MIN(a, b) (((a) < (b)) ? (a) : (b))
  #define MEMCPY memcpy
#endif

#ifdef _WIN32

// From Libfuzzer
// Intermediate macro to ensure the parameter is expanded before stringified.
#define STRINGIFY_(A) #A
#define STRINGIFY(A) STRINGIFY_(A)

#if _MSC_VER
// Copied from compiler-rt/lib/sanitizer_common/sanitizer_win_defs.h
#if defined(_M_IX86) || defined(__i386__)
#define WIN_SYM_PREFIX "_"
#else
#define WIN_SYM_PREFIX
#endif

// Declare external functions as having alternativenames, so that we can
// determine if they are not defined.
#define EXTERNAL_FUNC(Name, Default)                                   \
  __pragma(comment(linker, "/alternatename:" WIN_SYM_PREFIX STRINGIFY( \
                               Name) "=" WIN_SYM_PREFIX STRINGIFY(Default)))

#define CHECK_WEAK_FN(Name) ((void*)Name != (void*)&Name##Def)
#else
// Declare external functions as weak to allow them to default to a specified
// function if not defined explicitly. We must use weak symbols because clang's
// support for alternatename is not 100%, see
// https://bugs.llvm.org/show_bug.cgi?id=40218 for more details.
#define EXTERNAL_FUNC(Name, Default) \
  __attribute__((weak, alias(STRINGIFY(Default))))

#define CHECK_WEAK_FN(Name) (Name != NULL)
#endif  // _MSC_VER

#define EXT_FUNC_DEF(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
  EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)
#define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
  EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)

#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)         \
  RETURN_TYPE (*NAME##Def) FUNC_SIG = NULL;                 \
  EXTERNAL_FUNC(NAME, NAME##Def) RETURN_TYPE NAME FUNC_SIG
#else

#if defined(__APPLE__)
  // TODO: Find a proper way to deal with weak fns on Apple!
  // On Apple, weak_import and weak attrs behave differently to linux.
  #define EXT_FUNC_DEF(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
    EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN) { return (RETURN_TYPE) 0; }

  #define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)      \
  RETURN_TYPE NAME FUNC_SIG __attribute__((weak_import)) { \
      return (RETURN_TYPE) 0;                              \
  }

  #define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
  __attribute__((weak, visibility("default"))) RETURN_TYPE NAME FUNC_SIG

#else

#define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
  EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)

// Declare these symbols as weak to allow them to be optionally defined.
#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)                            \
  __attribute__((weak, visibility("default"))) RETURN_TYPE NAME FUNC_SIG
#endif

#define CHECK_WEAK_FN(Name) (Name != NULL)
#endif

#endif
