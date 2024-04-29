/*
   LibAFL - Coverage accounting LLVM pass
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include "common-llvm.h"

#include <time.h>

#include <list>
#include <string>
#include <fstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"

// Without this, Can't build with llvm-14 & old PM
#if LLVM_VERSION_MAJOR >= 14 && !defined(USE_NEW_PM)
  #include "llvm/Pass.h"
#endif

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

typedef uint32_t prev_loc_t;

#define MAP_SIZE ACCOUNTING_MAP_SIZE

#define SECURITY_SENSITIVE_FUNCS(CF)                          \
  static CF securitySensitiveFunctions[] = {                  \
      /* mem allocations */                                   \
      CF("malloc"),                                           \
      CF("calloc"),                                           \
      CF("realloc"),                                          \
      CF("reallocarray"),                                     \
      CF("memalign"),                                         \
      CF("__libc_memalign"),                                  \
      CF("aligned_alloc"),                                    \
      CF("posix_memalign"),                                   \
      CF("valloc"),                                           \
      CF("pvalloc"),                                          \
      CF("mmap"), /* memory frees */                          \
      CF("free"),                                             \
      CF("cfree"),                                            \
      CF("munmap"), /* mem operations */                      \
      CF("memcmp"),                                           \
      CF("memcpy"),                                           \
      CF("mempcpy"),                                          \
      CF("memmove"),                                          \
      CF("memset"),                                           \
      CF("memchr"),                                           \
      CF("memrchr"),                                          \
      CF("memmem"),                                           \
      CF("bzero"),                                            \
      CF("explicit_bzero"),                                   \
      CF("bcmp"), /* strings */                               \
      CF("strlen"),                                           \
      CF("strnlen"),                                          \
      CF("strcpy"),                                           \
      CF("strncpy"),                                          \
      CF("strerror"),                                         \
      CF("strcat"),                                           \
      CF("strncat"),                                          \
      CF("strcmp"),                                           \
      CF("strspn"),                                           \
      CF("strcoll"),                                          \
      CF("strncmp"),                                          \
      CF("strxfrm"),                                          \
      CF("strstr"),                                           \
      CF("strchr"),                                           \
      CF("strscpn"),                                          \
      CF("strpbrk"),                                          \
      CF("strrchr"),                                          \
      CF("strtok"),                                           \
      CF("strcasecmp"),                                       \
      CF("strncasecmp"),                                      \
      CF("strcasestr"),                                       \
      CF("atoi"),                                             \
      CF("atol"),                                             \
      CF("atoll"),                                            \
      CF("wcslen"),                                           \
      CF("wcscpy"),                                           \
      CF("wcscmp"),                                           \
      CF("stpcpy"),                                           \
      CF("strdup"), /* c++ new */                             \
      CF("_Znam"),                                            \
      CF("_ZnamRKSt9nothrow_t"),                              \
      CF("_ZnamSt11align_val_t"),                             \
      CF("_ZnamSt11align_val_tRKSt9nothrow_t"),               \
      CF("_Znwm"),                                            \
      CF("_ZnwmRKSt9nothrow_t"),                              \
      CF("_ZnwmSt11align_val_t"),                             \
      CF("_ZnwmSt11align_val_tRKSt9nothrow_t"), /* c++ del */ \
      CF("_ZdaPv"),                                           \
      CF("_ZdaPvm"),                                          \
      CF("_ZdaPvmSt11align_val_t"),                           \
      CF("_ZdaPvRKSt9nothrow_t"),                             \
      CF("_ZdaPvSt11align_val_t"),                            \
      CF("_ZdaPvSt11align_val_tRKSt9nothrow_t"),              \
      CF("_ZdlPv"),                                           \
      CF("_ZdlPvm"),                                          \
      CF("_ZdlPvmSt11align_val_t"),                           \
      CF("_ZdlPvRKSt9nothrow_t"),                             \
      CF("_ZdlPvSt11align_val_t"),                            \
      CF("_ZdlPvSt11align_val_tRKSt9nothrow_t"), /* others */ \
      CF("ReadImage"),                                        \
      CF("free"),                                             \
      CF("delete"),                                           \
      CF("getString"),                                        \
      CF("vsprintf"),                                         \
      CF("GET_COLOR"),                                        \
      CF("read"),                                             \
      CF("load_bmp"),                                         \
      CF("huffcode"),                                         \
      CF("new"),                                              \
      CF("getName"),                                          \
      CF("write"),                                            \
      CF("png_load"),                                         \
  };

using namespace llvm;

enum AccountingGranularity {
  BB_GRAN,
  FUNC_GRAN,
  // LOOP,
  UKNOWN_GRAN
};

static cl::opt<bool>        Debug("debug-coverage-accounting",
                                  cl::desc("Debug prints"), cl::init(false),
                                  cl::NotHidden);
static cl::opt<std::string> GranularityStr(
    "granularity", cl::desc("Granularity of accounting (BB, FUNC)"),
    cl::init(std::string("BB")), cl::NotHidden);
static cl::opt<uint32_t> InstRatio(
    "inst_ratio_coverage_accounting",
    cl::desc("Instrumentation ratio in percentage"), cl::init(100),
    cl::NotHidden);
static cl::opt<bool> ThreadSafe("thread_safe_coverage_accounting",
                                cl::desc("Use the thread safe instrumentation"),
                                cl::init(false), cl::NotHidden);

namespace {

SECURITY_SENSITIVE_FUNCS(StringRef)

bool isSecuritySensitiveFunction(Function *F) {
  if (!F) { return 0; }
  auto func_name = F->getName();
  for (auto name : securitySensitiveFunctions) {
    if (func_name.contains(name)) {
      if (Debug)
        fprintf(stderr, "Counted %s as security sensitive",
                func_name.str().c_str());
      return 1;
    }
  }
  return 0;
}

#ifdef USE_NEW_PM
class AFLCoverage : public PassInfoMixin<AFLCoverage> {
 public:
  AFLCoverage() {
#else
class AFLCoverage : public ModulePass {
 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {
#endif
    granularity = StringSwitch<AccountingGranularity>(GranularityStr)
                      .Case("BB", BB_GRAN)
                      .Case("FUNC", FUNC_GRAN)
                      .Default(UKNOWN_GRAN);
    // initInstrumentList();
  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t              map_size = MAP_SIZE;
  uint32_t              function_minimum_size = 1;
  AccountingGranularity granularity;
};

}  // namespace

#ifdef USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AFLCoverageAccounting", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(AFLCoverage());
                });
  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {
              if (Name == "AFLCoverageAccounting") {
                MPM.addPass(AFLCoverage());
                return true;
              } else {
                return false;
              }
            });
  #endif
          }};
}
#else

char AFLCoverage::ID = 0;
#endif

#ifdef USE_NEW_PM
PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool AFLCoverage::runOnModule(Module &M) {
#endif

  LLVMContext &C = M.getContext();

  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  uint32_t     rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  /* Decide instrumentation ratio */

  if (!InstRatio || InstRatio > 100)
    FATAL("Bad value of the instrumentation ratio (must be between 1 and 100)");

  /* Get globals for the SHM region and the previous location. Note that
     __afl_acc_prev_loc is thread-local. */

  GlobalVariable *AFLMemOpPtr = new GlobalVariable(
      M, PointerType::get(Int32Ty, 0), false, GlobalValue::ExternalLinkage, 0,
      "__afl_acc_memop_ptr");

  GlobalVariable *AFLPrevLoc;

#if defined(__ANDROID__) || defined(__HAIKU__)
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_acc_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_acc_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

  /* Instrument all the things! */

  int inst_blocks = 0;
  // scanForDangerousFunctions(&M);

  for (auto &F : M) {
    int has_calls = 0;
    if (Debug)
      fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
              F.size());

    // if (!isInInstrumentList(&F)) { continue; }

    if (F.size() < function_minimum_size) { continue; }

    std::list<Value *> todo;
    for (auto &BB : F) {
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (RandBelow(100) >= InstRatio) { continue; }

      // Start with 1 to implicitly track edge coverage too
      uint32_t MemCnt = 1;
      for (auto &I : BB) {
        switch (granularity) {
          case BB_GRAN: {
            if (I.mayReadFromMemory() || I.mayWriteToMemory()) { ++MemCnt; }
            break;
          }
          case FUNC_GRAN: {
            if (auto *C = dyn_cast<CallInst>(&I)) {
              auto F = C->getCalledFunction();
              MemCnt += isSecuritySensitiveFunction(F);
            }
            break;
          }
        }
      }
      /* Make up cur_loc */

      cur_loc = RandBelow(map_size);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          Int32Ty,
#endif
          AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Load SHM pointer */

      LoadInst *MemReadPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int32Ty, 0),
#endif
          AFLMemOpPtr);
      MemReadPtr->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
      Value *MemReadPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
          Int32Ty,
#endif
          MemReadPtr, IRB.CreateXor(PrevLoc, CurLoc));

      /* Update bitmap */

      LoadInst *MemReadCount = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          Int32Ty,
#endif
          MemReadPtrIdx);
      MemReadCount->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));
      Value *MemReadIncr =
          IRB.CreateAdd(MemReadCount, ConstantInt::get(Int32Ty, MemCnt));
      IRB.CreateStore(MemReadIncr, MemReadPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Update prev_loc */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;
    }
  }

  if (Debug) {
    if (!inst_blocks)
      fprintf(stderr, "No instrumentation targets found.\n");
    else
      fprintf(stderr, "Instrumented %d locations (ratio %u%%).\n", inst_blocks,
              (unsigned)InstRatio);
  }

#ifdef USE_NEW_PM
  return PA;
#else
  return true;
#endif
}

#ifndef USE_NEW_PM
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
#endif
