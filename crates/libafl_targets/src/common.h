#ifndef __LIBAFL_TARGETS_COMMON__
#define __LIBAFL_TARGETS_COMMON__

#include <stdint.h>

#define true 1
#define false 0

#if !defined(_WIN32) && defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
typedef uint128_t         u128;
#endif

#define STATIC_ASSERT(pred) \
  switch (0) {              \
    case 0:                 \
    case pred:;             \
  }

// From https://stackoverflow.com/a/18298965
#if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
  #define THREAD_LOCAL _Thread_local
#elif defined _WIN32 && (defined _MSC_VER || defined __ICL || \
                         defined __DMC__ || defined __BORLANDC__)
  #define THREAD_LOCAL __declspec(thread)
/* note that ICC (linux) and Clang are covered by __GNUC__ */
#elif defined __GNUC__ || defined __SUNPRO_C || defined __xlC__
  #define THREAD_LOCAL __thread
#endif

#if defined(__ANDROID__) || defined(__HAIKU__)
  #undef THREAD_LOCAL
#elif defined(__APPLE__)
  #include <TargetConditionals.h>
  #if TARGET_OS_IPHONE
    #undef THREAD_LOCAL
  #endif
#endif

#ifdef THREAD_LOCAL
  #define MAYBE_THREAD_LOCAL THREAD_LOCAL
#else
  #define MAYBE_THREAD_LOCAL
#endif

#if defined _WIN32 && defined(_MSC_VER)
  #define RETADDR (uintptr_t) _ReturnAddress()
  #define EXPORT_FN __declspec(dllexport)
#else
  #define RETADDR (uintptr_t) __builtin_return_address(0)
  #define EXPORT_FN
#endif

#if __GNUC__ < 6
  #ifndef likely
    #define likely(_x) (_x)
  #endif
  #ifndef unlikely
    #define unlikely(_x) (_x)
  #endif
#else
  #ifndef likely
    #define likely(_x) __builtin_expect(!!(_x), 1)
  #endif
  #ifndef unlikely
    #define unlikely(_x) __builtin_expect(!!(_x), 0)
  #endif
#endif

#ifdef __GNUC__
  #define MAX(a, b)           \
    ({                        \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b;      \
    })
  #define MIN(a, b)           \
    ({                        \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a < _b ? _a : _b;      \
    })
  #define MEMCPY __builtin_memcpy
#else
  #include <string.h>  // needed to use memcpy on windows
  #define MAX(a, b) (((a) > (b)) ? (a) : (b))
  #define MIN(a, b) (((a) < (b)) ? (a) : (b))
  #define MEMCPY memcpy
#endif

#if defined _WIN32
  #if _MSC_VER
    // From Libfuzzer
    // Intermediate macro to ensure the parameter is expanded before stringified.
    #define STRINGIFY_(A) #A
    #define STRINGIFY(A) STRINGIFY_(A)

    // Copied from compiler-rt/lib/sanitizer_common/sanitizer_win_defs.h
    #if defined(_M_IX86) || defined(__i386__)
      #define WIN_SYM_PREFIX "_"
    #else
      #define WIN_SYM_PREFIX
    #endif

    // Declare external functions as having alternativenames, so that we can
    // determine if they are not defined.
    #define EXTERNAL_FUNC(Name, Default)                              \
      __pragma(                                                       \
          comment(linker, "/alternatename:" WIN_SYM_PREFIX STRINGIFY( \
                              Name) "=" WIN_SYM_PREFIX STRINGIFY(Default)))

    #define CHECK_WEAK_FN(Name) ((void *)Name != (void *)&Name##Def)

    #define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN)    \
      RETURN_TYPE NAME##Def                           FUNC_SIG; \
      EXTERNAL_FUNC(NAME, NAME##Def) RETURN_TYPE NAME FUNC_SIG; \
      RETURN_TYPE NAME##Def FUNC_SIG

    #define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      RETURN_TYPE(*NAME##Def) FUNC_SIG = NULL;          \
      EXTERNAL_FUNC(NAME, NAME##Def) RETURN_TYPE NAME FUNC_SIG
  #else
    // Declare external functions as weak to allow them to default to a
    // specified function if not defined explicitly. We must use weak symbols
    // because clang's support for alternatename is not 100%, see
    // https://bugs.llvm.org/show_bug.cgi?id=40218 for more details.
    #define EXTERNAL_FUNC(Name, Default) \
      __attribute__((weak, alias(STRINGIFY(Default))))

    #define CHECK_WEAK_FN(Name) (Name != NULL)

    #define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)

    #define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      RETURN_TYPE(*NAME##Def) FUNC_SIG = NULL;          \
      EXTERNAL_FUNC(NAME, NAME##Def) RETURN_TYPE NAME FUNC_SIG
  #endif  // _MSC_VER

#else

  #if defined(__APPLE__)
    #define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)

    // Declare these symbols as weak to allow them to be optionally defined.
    #define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      __attribute__((weak, visibility("default"))) RETURN_TYPE NAME FUNC_SIG

    // Weakly defined globals
    #define EXT_VAR(NAME, TYPE) \
      TYPE __attribute__((weak, visibility("default"))) NAME

  #else

    #define EXT_FUNC_IMPL(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)

    // Declare these symbols as weak to allow them to be optionally defined.
    #define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN) \
      __attribute__((weak, visibility("default"))) RETURN_TYPE NAME FUNC_SIG

    // Weakly defined globals
    #define EXT_VAR(NAME, TYPE) \
      TYPE __attribute__((weak, visibility("default"))) NAME

  #endif

  #define CHECK_WEAK_FN(Name) (Name != NULL)
#endif  // _WIN32

#endif
