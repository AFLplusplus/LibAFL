#ifndef LIBAFL_EXIT_H
#define LIBAFL_EXIT_H

#define STRINGIFY(s) #s
#define XSTRINGIFY(s) STRINGIFY(s)

// Target Specific imports / definitions
#ifdef _WIN32
  #include <stdint.h>
  #include <intsafe.h>

typedef UINT64 libafl_word;
  #define LIBAFL_CALLING_CONVENTION __fastcall

#else
  #ifdef __x86_64__
    #include <stdint.h>

typedef uint64_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif

  #ifdef __arm__
    #include <stdint.h>

typedef uint32_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif
#endif

#define LIBAFL_EXIT_OPCODE 0x66f23a0f
#define LIBAFL_EXIT_VERSION_NUMBER 0111  // TODO: find a nice way to set it.

typedef enum LibaflExit {
  LIBAFL_EXIT_START_VIRT = 0,
  LIBAFL_EXIT_START_PHYS = 1,
  LIBAFL_EXIT_INPUT_VIRT = 2,
  LIBAFL_EXIT_INPUT_PHYS = 3,
  LIBAFL_EXIT_END = 4,
  LIBAFL_EXIT_SAVE = 5,
  LIBAFL_EXIT_LOAD = 6,
  LIBAFL_EXIT_VERSION = 7,
  LIBAFL_EXIT_VADDR_FILTER_ALLOW = 8,
} LibaflExit;

typedef enum LibaflExitEndStatus {
  LIBAFL_EXIT_END_UNKNOWN = 0,
  LIBAFL_EXIT_END_OK = 1,
  LIBAFL_EXIT_END_CRASH = 2,
} LibaflExitEndParams;

#ifdef _WIN32
  #ifdef __cplusplus
extern "C" {
  #endif
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call0(libafl_word action);
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call1(libafl_word action,
                                                         libafl_word arg1);
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call2(libafl_word action,
                                                         libafl_word arg1,
                                                         libafl_word arg2);
  #ifdef __cplusplus
}
  #endif
#else

  #ifdef __x86_64__
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call0(libafl_word action) {
  libafl_word ret;
  __asm__ volatile (
        "mov %1, %%rax\n"
        ".dword " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
        "mov %%rax, %0\n"
        : "=g"(ret)
        : "g"(action)
        : "%rax"
    );
  return ret;
}

libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call1(libafl_word action,
                                                         libafl_word arg1) {
  libafl_word ret;
  __asm__ volatile (
      "mov %1, %%rax\n"
      "mov %2, %%rdi\n"
      ".dword " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
      "mov %%rax, %0\n"
      : "=g"(ret)
      : "g"(action), "g"(arg1)
      : "%rax", "%rdi"
      );
  return ret;
}

libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call2(libafl_word action,
                                                         libafl_word arg1,
                                                         libafl_word arg2) {
  libafl_word ret;
  __asm__ volatile (
      "mov %1, %%rax\n"
      "mov %2, %%rdi\n"
      "mov %3, %%rsi\n"
      ".dword " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
      "mov %%rax, %0\n"
      : "=g"(ret)
      : "g"(action), "g"(arg1), "g"(arg2)
      : "%rax", "%rdi", "%rsi"
      );
  return ret;
}
  #endif

  #ifdef __arm__
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call0(libafl_word action) {
  libafl_word ret;
  __asm__ volatile (
      "mov r0, %1\n"
      ".word " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
      "mov %0, r0\n"
      : "=r"(ret)
      : "r"(action)
      : "r0"
  );
  return ret;
}

libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call1(libafl_word action,
                                                         libafl_word arg1) {
  libafl_word ret;
  __asm__ volatile (
      "mov r0, %1\n"
      "mov r1, %2\n"
      ".word " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
      "mov %0, r0\n"
      : "=r"(ret)
      : "r"(action), "r"(arg1)
      : "r0", "r1"
  );
  return ret;
}

libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call2(libafl_word action,
                                                         libafl_word arg1,
                                                         libafl_word arg2) {
  libafl_word ret;
  __asm__ volatile (
      "mov r0, %1\n"
      "mov r1, %2\n"
      "mov r2, %3\n"
      ".word " XSTRINGIFY(LIBAFL_EXIT_OPCODE) "\n"
      "mov %0, r0\n"
      : "=r"(ret)
      : "r"(action), "r"(arg1), "r"(arg2)
      : "r0", "r1", "r2"
  );
  return ret;
}
  #endif

#endif

#define LIBAFL_EXIT_START_VIRT(buf_vaddr, max_len) \
  _libafl_exit_call2(LIBAFL_EXIT_START_VIRT, buf_vaddr, max_len)
#define LIBAFL_EXIT_START_PHYS(buf_paddr, max_len) \
  _libafl_exit_call2(LIBAFL_EXIT_START_PHYS, buf_paddr, max_len)
#define LIBAFL_EXIT_INPUT_VIRT(buf_vaddr, max_len) \
  _libafl_exit_call2(LIBAFL_EXIT_INPUT_VIRT, buf_vaddr, max_len)
#define LIBAFL_EXIT_INPUT_PHYS(buf_paddr, max_len) \
  _libafl_exit_call2(LIBAFL_EXIT_INPUT_PHYS, buf_paddr, max_len)
#define LIBAFL_EXIT_END(status) _libafl_exit_call1(LIBAFL_EXIT_END, status)
#define LIBAFL_EXIT_SAVE() _libafl_exit_call0(LIBAFL_EXIT_SAVE)
#define LIBAFL_EXIT_LOAD() _libafl_exit_call0(LIBAFL_EXIT_LOAD)
#define LIBAFL_EXIT_VERSION() _libafl_exit_call0(LIBAFL_EXIT_VERSION_NUMBER)

#endif