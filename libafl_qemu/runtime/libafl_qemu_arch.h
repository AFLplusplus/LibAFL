#ifndef LIBAFL_QEMU_ARCH
#define LIBAFL_QEMU_ARCH

// TODO: slit this in subfiles?

#include "libafl_qemu_defs.h"

/* Arch-specific definitions
 *
 * Each architecture should define:
 *  - [type] libafl_word: native word on the target architecture (often the size of a register)
 *  - [macro] define STDIO_SUPPORT: if defined, more commands will be supported.
 *  - [macro] LIBAFL_CALLING_CONVENTION: the calling convention to follow for the architecture. it should be the same as the one use in libafl qemu.
 *  - [function] snprintf: the standard POSIX snprintf definition.
 *  - [function] va_{start,arg,end}: standard functions to handle variadic functions
 */

// Target Specific imports / definitions
#if defined(_WIN32)
    // Windows
    #include <stdint.h>
    #include <intsafe.h>

    typedef UINT64 libafl_word;
    #define LIBAFL_CALLING_CONVENTION __fastcall
    #define STDIO_SUPPORT
#elif defined(__linux__)
    // Linux
    #ifdef __KERNEL__
      // Linux kernel
      #include <asm-generic/int-ll64.h>

      #if defined(__x86_64__) || defined(__aarch64__)
        typedef __u64 libafl_word;
        #define LIBAFL_CALLING_CONVENTION __attribute__(())
      #endif

      #ifdef __arm__
        typedef __u32 libafl_word;
        #define LIBAFL_CALLING_CONVENTION __attribute__(())
      #endif
    #else
      // Linux userland
      #include <stdio.h>
      #include <stdint.h>
      #include <stdarg.h>

      #define noinline __attribute__((noinline))

      #if defined(__x86_64__) || defined(__aarch64__)
        typedef uint64_t libafl_word;
        #define LIBAFL_CALLING_CONVENTION __attribute__(())
      #endif

      #ifdef __arm__
        typedef uint32_t libafl_word;
        #define LIBAFL_CALLING_CONVENTION __attribute__(())
      #endif
    #endif

    #define STDIO_SUPPORT
#else
    // Other
    #include <stdint.h>
    #include <stdarg.h>

    #define noinline __attribute__((noinline))

    #if defined(__x86_64__) || defined(__aarch64__)
      typedef uint64_t libafl_word;
      #define LIBAFL_CALLING_CONVENTION __attribute__(())
    #endif

    #ifdef __arm__
      typedef uint32_t libafl_word;
      #define LIBAFL_CALLING_CONVENTION __attribute__(())
    #endif
#endif
#endif

#ifdef _WIN32
    #define LIBAFL_DEFINE_FUNCTIONS(name, _opcode) \
      #ifdef __cplusplus \
        extern "C" { \
      #endif \
          libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(libafl_word action); \
          libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(libafl_word action, \
                                                        ##name##  libafl_word arg1); \
          libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(libafl_word action, \
                                                                   libafl_word arg1, \
                                                                   libafl_word arg2); \
      #ifdef __cplusplus \
        } \
      #endif
#else
  #if defined(__x86_64__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
              "mov %1, %%rax\n"                                                                   \
              ".4byte " XSTRINGIFY(opcode) "\n"                                                   \
              "mov %%rax, %0\n"                                                                   \
              : "=g"(ret)                                                                         \
              : "g"(action)                                                                       \
              : "%rax"                                                                            \
          ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
            "mov %1, %%rax\n"                                                                     \
            "mov %2, %%rdi\n"                                                                     \
            ".4byte " XSTRINGIFY(opcode) "\n"                                                     \
            "mov %%rax, %0\n"                                                                     \
            : "=g"(ret)                                                                           \
            : "g"(action), "g"(arg1)                                                              \
            : "%rax", "%rdi"                                                                      \
            ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov %1, %%rax\n"                                                                         \
        "mov %2, %%rdi\n"                                                                         \
        "mov %3, %%rsi\n"                                                                         \
        ".4byte " XSTRINGIFY(opcode) "\n"                                                         \
        "mov %%rax, %0\n"                                                                         \
        : "=g"(ret)                                                                               \
        : "g"(action), "g"(arg1), "g"(arg2)                                                       \
        : "%rax", "%rdi", "%rsi"                                                                  \
        ); \
        return ret;                                                                                 \
      }

  #elif defined(__arm__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov r0, %1\n"                                                                            \
        ".word " XSTRINGIFY(opcode) "\n"                                              \
        "mov %0, r0\n"                                                                            \
        : "=r"(ret)                                                                               \
        : "r"(action)                                                                             \
        : "r0"                                                                                    \
    ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov r0, %1\n"                                                                      \
        "mov r1, %2\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, r0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1)                                                            \
        : "r0", "r1"                                                                        \
    );   \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov r0, %1\n"                                                                      \
        "mov r1, %2\n"                                                                      \
        "mov r2, %3\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, r0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1), "r"(arg2)                                                 \
        : "r0", "r1", "r2"                                                                  \
    );   \
        return ret;                                                                                 \
      }

  #elif defined(__aarch64__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov x0, %1\n"                                                                            \
        ".word " XSTRINGIFY(opcode) "\n"                                              \
        "mov %0, x0\n"                                                                            \
        : "=r"(ret)                                                                               \
        : "r"(action)                                                                             \
        : "x0"                                                                                    \
    ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov x0, %1\n"                                                                      \
        "mov x1, %2\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, x0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1)                                                            \
        : "x0", "x1"                                                                        \
    );   \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov x0, %1\n"                                                                      \
        "mov x1, %2\n"                                                                      \
        "mov x2, %3\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, x0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1), "r"(arg2)                                                 \
        : "x0", "x1", "x2"                                                                  \
    );   \
        return ret;                                                                                 \
      }
  #elif defined(__riscv)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mv a0, %1\n"                                                                            \
        ".word " XSTRINGIFY(opcode) "\n"                                              \
        "mv a0, a0\n"                                                                            \
        : "=r"(ret)                                                                               \
        : "r"(action)                                                                             \
        : "a0"                                                                                    \
    ); \
        return ret;                                                                               \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mv a0, %1\n"                                                                      \
        "mv a1, %2\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mv %0, a0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1)                                                            \
        : "a0", "a1"                                                                        \
    );   \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mv a0, %1\n"                                                                      \
        "mv a1, %2\n"                                                                      \
        "mv a2, %3\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mv %0, a0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1), "r"(arg2)                                                 \
        : "a0", "a1", "a2"                                                                  \
    );   \
        return ret;                                                                                 \
      }

  #else
    #warning "LibAFL QEMU Runtime does not support your architecture yet, please leave an issue."
  #endif

// Generates sync exit functions
LIBAFL_DEFINE_FUNCTIONS(sync_exit, LIBAFL_SYNC_EXIT_OPCODE)

// Generates backdoor functions
LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)

STATIC_CHECKS

#endif
