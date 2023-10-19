/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/
#include <stdio.h>
#include <stdlib.h>
#include "common-llvm.h"
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/time.h>
#endif

#include <list>
#include <string>
#include <fstream>
#include "llvm/Config/llvm-config.h"

#if USE_NEW_PM
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>

#define COVERAGE_MAP_SIZE LIBAFL_EDGES_MAP_SIZE

using namespace llvm;
namespace {

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
bool isIgnoreFunction(const llvm::Function *F) {
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
    if (F->getName().startswith(ignoreListFunc)) { return true; }
  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan",       "__msan",     "__ubsan", "__lsan",
      "__san",        "__sanitize", "__cxx",   "_GLOBAL__",
      "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {
    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }
  }

  return false;
}

#if USE_NEW_PM
class CtxLogging : public PassInfoMixin<CtxLogging> {
 public:
  CtxLogging() {
  }
#else

class CtxLogging : public ModulePass {
 public:
  static char ID;
  CtxLogging() : ModulePass(ID) {
  }
#endif

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool        runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {
  #else
  StringRef getPassName() const override {
  #endif
    return "ctx logging";
  }
#endif

 private:
  uint32_t function_minimum_size = 1;
  uint32_t coverage_map_size =
      std::getenv("LIBAFL_CMP_MAP_SIZE")
          ? std::stoi(std::getenv("LIBAFL_CMP_MAP_SIZE"))
          : 65536;
  bool hookCalls(Module &M);
  bool be_quiet = true;
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CtxLogging", "v0.1", [](PassBuilder &PB) {
  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
  #if LLVM_VERSION_MAJOR >= 16
            PB.registerOptimizerEarlyEPCallback(
  #else
            PB.registerOptimizerLastEPCallback(
  #endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(CtxLogging());
                });
          }};
}
#else
char CtxLogging::ID = 0;
#endif

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {
  while (first != last) {
    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;
  }

  return last;
}

bool CtxLogging::hookCalls(Module &M) {
  LLVMContext &C = M.getContext();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int128Ty = IntegerType::getInt128Ty(C);

  Constant *Null = Constant::getNullValue(PointerType::get(Int8Ty, 0));

  // For ctx
  GlobalVariable *AFLContext = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
  Value *PrevCtx = NULL;

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {
    if (isIgnoreFunction(&F)) continue;
    int has_calls = 0;
    for (auto &BB : F) {
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          InitialIRB(&(*IP));
      if (&BB == &F.getEntryBlock()) {
        // at the first basic block
        // load the context id of the previous function and write to a local
        // variable on the stack

        LoadInst *PrevCtxLoad = InitialIRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            InitialIRB.getInt32Ty(),
#endif
            AFLContext);
        PrevCtxLoad->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));
        PrevCtx = PrevCtxLoad;

        // Next check if there are fucntion calls in this function

        // does the function have calls? and is any of the calls larger than
        // one basic block?
        for (auto &BB_2 : F) {
          if (has_calls) { break; }
          for (auto &IN : BB_2) {
            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {
              Function *Callee = callInst->getCalledFunction();
              if (!Callee || Callee->size() < function_minimum_size) {
                continue;
              } else {
                has_calls = 1;
                break;
              }
            }
          }
        }

        // if yes we store a context ID for this function in the global var
        if (has_calls) {
          // if we reach here it means that we are in a function in which we
          // have call instruction into other functions let's give this
          // function a random 32bit number
          Value *NewCtx =
              ConstantInt::get(Int32Ty, RandBelow(coverage_map_size));

          NewCtx = InitialIRB.CreateXor(PrevCtx, NewCtx);
          StoreInst *StoreCtx = InitialIRB.CreateStore(NewCtx, AFLContext);
          StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));
        }
      }

      if (has_calls) {
        Instruction *Inst = BB.getTerminator();
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
          IRBuilder<> LastIRB(Inst);
          StoreInst  *RestoreCtx = LastIRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
        }
      }
    }
  }
  return true;
}

#if USE_NEW_PM
PreservedAnalyses CtxLogging::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool CtxLogging::runOnModule(Module &M) {
#endif
  hookCalls(M);

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif
  verifyModule(M);

#if USE_NEW_PM
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM
#else
static void registerCtxLoggingPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  auto p = new CtxLogging();
  PM.add(p);
}

static RegisterStandardPasses RegisterCtxLoggingPass(
    PassManagerBuilder::EP_OptimizerLast, registerCtxLoggingPass);

static RegisterStandardPasses RegisterCtxLoggingPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCtxLoggingPass);

static RegisterStandardPasses RegisterCtxLoggingPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCtxLoggingPass);

#endif
