#ifndef LIBAFL_COMMON_LLVM_H
#define LIBAFL_COMMON_LLVM_H

#include <stdio.h>
#include <stdlib.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#if LLVM_VERSION_MAJOR >= 7 /* use new pass manager */
//#define USE_NEW_PM 1
#endif

/* #if LLVM_VERSION_STRING >= "4.0.1" */
#if LLVM_VERSION_MAJOR > 4 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
  #define HAVE_VECTOR_INTRINSICS 1
#endif

#ifdef USE_NEW_PM
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#else
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#define FATAL(...) do { fprintf(stderr, "FATAL: " __VA_ARGS__); exit(1); } while (0)

static uint32_t RandBelow(uint32_t max) {
    return (uint32_t)rand() % (max +1);
}

/* needed up to 3.9.0 */
#if LLVM_VERSION_MAJOR == 3 && \
    (LLVM_VERSION_MINOR < 9 || \
     (LLVM_VERSION_MINOR == 9 && LLVM_VERSION_PATCH < 1))
static uint64_t PowerOf2Ceil(unsigned in) {

  uint64_t in64 = in - 1;
  in64 |= (in64 >> 1);
  in64 |= (in64 >> 2);
  in64 |= (in64 >> 4);
  in64 |= (in64 >> 8);
  in64 |= (in64 >> 16);
  in64 |= (in64 >> 32);
  return in64 + 1;

}
#endif

#endif // LIBAFL_COMMON_LLVM_H
