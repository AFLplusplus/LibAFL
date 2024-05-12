#ifndef LIBAFL_QEMU_H
#define LIBAFL_QEMU_H

/**
 * LibAFL QEMU header file.
 *
 * This file is a portable header file used to build target harnesses more
 * conveniently. Its main purpose is to generate ready-to-use calls to
 * communicate with the fuzzer. The list of commands is available at the bottom
 * of this file. The rest mostly consists of macros generating the code used by
 * the commands.
 */

/* === The private part starts here === */

/* This part should not be useful for most people. Callable commands are
 * available at the end of this file. */

#define STRINGIFY(s) #s
#define XSTRINGIFY(s) STRINGIFY(s)

// Target Specific imports / definitions
#ifdef _WIN32
  #include <stdint.h>
  #include <intsafe.h>

typedef UINT64 libafl_word;
  #define LIBAFL_CALLING_CONVENTION __fastcall

#else
  #include <stdint.h>

  #if defined(__x86_64__) || defined(__aarch64__)
    typedef uint64_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif

  #ifdef __arm__
    typedef uint32_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif
#endif

#define LIBAFL_SYNC_EXIT_OPCODE 0x66f23a0f
#define LIBAFL_BACKDOOR_OPCODE 0x44f23a0f

#define LIBAFL_QEMU_HDR_VERSION_NUMBER 0111  // TODO: find a nice way to set it.

typedef enum LibaflQemuCommand {
  LIBAFL_QEMU_COMMAND_START_VIRT = 0,
  LIBAFL_QEMU_COMMAND_START_PHYS = 1,
  LIBAFL_QEMU_COMMAND_INPUT_VIRT = 2,
  LIBAFL_QEMU_COMMAND_INPUT_PHYS = 3,
  LIBAFL_QEMU_COMMAND_END = 4,
  LIBAFL_QEMU_COMMAND_SAVE = 5,
  LIBAFL_QEMU_COMMAND_LOAD = 6,
  LIBAFL_QEMU_COMMAND_VERSION = 7,
  LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW = 8,
} LibaflExit;

typedef enum LibaflQemuEndStatus {
  LIBAFL_QEMU_END_UNKNOWN = 0,
  LIBAFL_QEMU_END_OK = 1,
  LIBAFL_QEMU_END_CRASH = 2,
} LibaflExitEndParams;

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
              ".dword " XSTRINGIFY(opcode) "\n"                                                   \
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
            ".dword " XSTRINGIFY(opcode) "\n"                                                     \
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
        ".dword " XSTRINGIFY(opcode) "\n"                                                         \
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
  #else
    #warning "LibAFL QEMU Runtime does not support your architecture yet, please leave an issue."
  #endif

#endif

// Generates sync exit functions
LIBAFL_DEFINE_FUNCTIONS(sync_exit, LIBAFL_SYNC_EXIT_OPCODE)

// Generates backdoor functions
LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)

/* === The private part ends here === */

/* === The public part starts here === */

/* LibAFL QEMU Commands */

#define LIBAFL_QEMU_START_VIRT(buf_vaddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_VIRT, buf_vaddr, max_len)

#define LIBAFL_QEMU_START_PHYS(buf_paddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_PHYS, buf_paddr, max_len)

#define LIBAFL_QEMU_INPUT_VIRT(buf_vaddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_VIRT, buf_vaddr, max_len)

#define LIBAFL_QEMU_INPUT_PHYS(buf_paddr, max_len) \
  _libafl_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_PHYS, buf_paddr, max_len)

#define LIBAFL_QEMU_END(status) _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_END, status)

#define LIBAFL_QEMU_SAVE() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_SAVE)

#define LIBAFL_QEMU_LOAD() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_LOAD)

#define LIBAFL_QEMU_VERSION() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_VERSION)

/* === The public part ends here === */

#endif
