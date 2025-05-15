#ifndef LIBAFL_COMMON_LLVM_H
#define LIBAFL_COMMON_LLVM_H

#include <stdio.h>
#include <stdlib.h>

#include "llvm/Config/llvm-config.h"

/* #if LLVM_VERSION_STRING >= "4.0.1" */
#define HAVE_VECTOR_INTRINSICS 1

#include <optional>
#if LLVM_VERSION_MAJOR >= 16
// None constant being deprecated for LLVM-16, it is recommended
// to use the std::nullopt_t type instead. (#1010)
constexpr std::nullopt_t None = std::nullopt;
#endif

// all llvm includes and friends
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/CFG.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

#define FATAL(...)                          \
  do {                                      \
    fprintf(stderr, "FATAL: " __VA_ARGS__); \
    exit(1);                                \
  } while (0)

static uint32_t RandBelow(uint32_t max) {
  return (uint32_t)rand() % (max + 1);
}

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
static inline bool isIgnoreFunction(const llvm::Function *F) {
  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {

      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan",
      "ign.",
      "__afl",
      "_fini",
      "__libc_",
      "__asan",
      "__msan",
      "__cmplog",
      "__sancov",
      "__san",
      "__cxx_",
      "__decide_deferred",
      "_GLOBAL",
      "_ZZN6__asan",
      "_ZZN6__lsan",
      "msan.",
      "LLVMFuzzerM",
      "LLVMFuzzerC",
      "LLVMFuzzerI",
      "maybe_duplicate_stderr",
      "discard_output",
      "close_stdout",
      "dup_and_close_stderr",
      "maybe_close_fd_mask",
      "ExecuteFilesOnyByOne"

  };

  for (auto const &ignoreListFunc : ignoreList) {
#if LLVM_VERSION_MAJOR >= 18
    if (F->getName().starts_with(ignoreListFunc)) { return true; }
#else
    if (F->getName().startswith(ignoreListFunc)) { return true; }
#endif
  }
  static constexpr const char *ignoreSubstringList[] = {

      "__asan",     "__msan",     "__ubsan",   "__lsan",
      "__san",      "__sanitize", "_GLOBAL__", "DebugCounter",
      "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {
    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (llvm::StringRef::npos != F->getName().find(ignoreListFunc)) {
      return true;
    }
  }

  return false;
}

#endif  // LIBAFL_COMMON_LLVM_H
