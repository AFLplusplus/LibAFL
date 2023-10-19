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

using namespace llvm;

static cl::opt<bool> CmplogExtended("cmplog_switches_extended",
                                    cl::desc("Uses extended header"),
                                    cl::init(false), cl::NotHidden);
namespace {

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
class CmpLogSwitches : public PassInfoMixin<CmpLogSwitches> {
 public:
  CmpLogSwitches() {
#else

class CmpLogSwitches : public ModulePass {
 public:
  static char ID;
  CmpLogSwitches() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool        runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {
  #else
  StringRef getPassName() const override {
  #endif
    return "cmplog switches";
  }
#endif

 private:
  bool hookInstrs(Module &M);
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CmpLogSwitches", "v0.1",
          [](PassBuilder &PB) {
  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(CmpLogSwitches());
                });
          }};
}
#else
char CmpLogSwitches::ID = 0;
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

bool CmpLogSwitches::hookInstrs(Module &M) {
  std::vector<SwitchInst *> switches;
  LLVMContext              &C = M.getContext();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

  FunctionCallee cmplogHookIns1;
  FunctionCallee cmplogHookIns2;
  FunctionCallee cmplogHookIns4;
  FunctionCallee cmplogHookIns8;

  if (CmplogExtended) {
    cmplogHookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1_extended",
                                           VoidTy, Int8Ty, Int8Ty, Int8Ty);
  } else {
    cmplogHookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty,
                                           Int8Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2_extended",
                                           VoidTy, Int16Ty, Int16Ty, Int8Ty);
  } else {
    cmplogHookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy,
                                           Int16Ty, Int16Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4_extended",
                                           VoidTy, Int32Ty, Int32Ty, Int8Ty);
  } else {
    cmplogHookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy,
                                           Int32Ty, Int32Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8_extended",
                                           VoidTy, Int64Ty, Int64Ty, Int8Ty);
  } else {
    cmplogHookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy,
                                           Int64Ty, Int64Ty, Int8Ty);
  }

  for (auto &F : M) {
    if (!isIgnoreFunction(&F)) { continue; }

    for (auto &BB : F) {
      SwitchInst *switchInst = nullptr;
      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {
        if (switchInst->getNumCases() > 1) { switches.push_back(switchInst); }
      }
    }
  }

  switches.erase(Unique(switches.begin(), switches.end()), switches.end());

  if (switches.size()) {
    for (auto &SI : switches) {
      Value        *Val = SI->getCondition();
      unsigned int  max_size = Val->getType()->getIntegerBitWidth();
      unsigned int  cast_size;
      unsigned char do_cast = 0;

      if (!SI->getNumCases() || max_size < 16) {
        // skipping trivial switch
        continue;
      }

      if (max_size % 8) {
        max_size = (((max_size / 8) + 1) * 8);
        do_cast = 1;
      }

      if (max_size > 128) {
        // can't handle this

        max_size = 128;
        do_cast = 1;
      }

      IRBuilder<> IRB(SI->getParent());
      IRB.SetInsertPoint(SI);

      switch (max_size) {
        case 8:
        case 16:
        case 32:
        case 64:
        case 128:
          cast_size = max_size;
          break;
        default:
          cast_size = 128;
          do_cast = 1;
      }

      // The predicate of the switch clause
      Value *CompareTo = Val;
      if (do_cast) {
        CompareTo =
            IRB.CreateIntCast(CompareTo, IntegerType::get(C, cast_size), false);
      }

      for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
           ++i) {
        // Who uses LLVM Major < 5?? :p
        ConstantInt *cint = i->getCaseValue();

        if (cint) {
          std::vector<Value *> args;
          args.push_back(CompareTo);

          Value *new_param = cint;
          if (do_cast) {
            new_param =
                IRB.CreateIntCast(cint, IntegerType::get(C, cast_size), false);
          }

          if (new_param) {
            args.push_back(new_param);
            if (CmplogExtended) {
              ConstantInt *attribute = ConstantInt::get(Int8Ty, 1);
              args.push_back(attribute);
            }
            if (cast_size != max_size) {
              // not 8, 16, 32, 64, 128.
              ConstantInt *bitsize =
                  ConstantInt::get(Int8Ty, (max_size / 8) - 1);
              args.push_back(bitsize);  // we have the arg for size in hookinsN
            }

            switch (cast_size) {
              case 8:
                IRB.CreateCall(cmplogHookIns1, args);
                break;
              case 16:
                IRB.CreateCall(cmplogHookIns2, args);
                break;
              case 32:
                IRB.CreateCall(cmplogHookIns4, args);
                break;
              case 64:
                IRB.CreateCall(cmplogHookIns8, args);
                break;
              case 128:
#ifdef WORD_SIZE_64
                if (max_size == 128) {
                  IRB.CreateCall(cmplogHookIns16, args);

                } else {
                  IRB.CreateCall(cmplogHookInsN, args);
                }

#endif
                break;
              default:
                break;
            }
          }
        }
      }
    }
  }
}

#if USE_NEW_PM
PreservedAnalyses CmpLogSwitches::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool CmpLogSwitches::runOnModule(Module &M) {
#endif
  hookInstrs(M);

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
static void registerCmpLogSwitchesPass(const PassManagerBuilder &,
                                       legacy::PassManagerBase &PM) {
  auto p = new CmpLogSwitches();
  PM.add(p);
}

static RegisterStandardPasses RegisterCmpLogSwitchesPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogSwitchesPass);

static RegisterStandardPasses RegisterCmpLogSwitchesPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogSwitchesPass);

static RegisterStandardPasses RegisterCmpLogSwitchesPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogSwitchesPass);

#endif