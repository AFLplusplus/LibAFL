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
#endif

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
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
class CmpLogRoutines : public PassInfoMixin<CmpLogRoutines> {
 public:
  CmpLogRoutines() {
#else

class CmpLogRoutines : public ModulePass {
 public:
  static char ID;
  CmpLogRoutines() : ModulePass(ID) {
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
    return "cmplog routines";
  }
#endif

 private:
  bool hookRtns(Module &M);
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CmpLogRoutines", "v0.1",
          [](PassBuilder &PB) {
  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(CmpLogRoutines());
                });
          }};
}
#else
char CmpLogRoutines::ID = 0;
#endif

bool CmpLogRoutines::hookRtns(Module &M) {
  std::vector<CallInst *> calls, llvmStdStd, llvmStdC, gccStdStd, gccStdC;
  LLVMContext            &C = M.getContext();

  Type *VoidTy = Type::getVoidTy(C);
  // PointerType *VoidPtrTy = PointerType::get(VoidTy, 0);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c = M.getOrInsertFunction("__cmplog_rtn_hook", VoidTy, i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                ,
                                NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookFn = cast<Function>(c);
#else
  FunctionCallee cmplogHookFn = c;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c1 = M.getOrInsertFunction("__cmplog_rtn_llvm_stdstring_stdstring",
                                 VoidTy, i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogLlvmStdStd = cast<Function>(c1);
#else
  FunctionCallee cmplogLlvmStdStd = c1;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c2 = M.getOrInsertFunction("__cmplog_rtn_llvm_stdstring_cstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogLlvmStdC = cast<Function>(c2);
#else
  FunctionCallee cmplogLlvmStdC = c2;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c3 = M.getOrInsertFunction("__cmplog_rtn_gcc_stdstring_stdstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogGccStdStd = cast<Function>(c3);
#else
  FunctionCallee cmplogGccStdStd = c3;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c4 = M.getOrInsertFunction("__cmplog_rtn_gcc_stdstring_cstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogGccStdC = cast<Function>(c4);
#else
  FunctionCallee cmplogGccStdC = c4;
#endif

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {
    if (isIgnoreFunction(&F)) { continue; }

    for (auto &BB : F) {
      for (auto &IN : BB) {
        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {
          Function *Callee = callInst->getCalledFunction();
          if (!Callee) { continue; }
          if (callInst->getCallingConv() != llvm::CallingConv::C) { continue; }

          FunctionType *FT = Callee->getFunctionType();

          bool isPtrRtn = FT->getNumParams() >= 2 &&
                          !FT->getReturnType()->isVoidTy() &&
                          FT->getParamType(0) == FT->getParamType(1) &&
                          FT->getParamType(0)->isPointerTy();

          bool isGccStdStringStdString =
              Callee->getName().find("__is_charIT_EE7__value") !=
                  std::string::npos &&
              Callee->getName().find(
                  "St7__cxx1112basic_stringIS2_St11char_traits") !=
                  std::string::npos &&
              FT->getNumParams() >= 2 &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0)->isPointerTy();

          bool isGccStdStringCString =
              Callee->getName().find(
                  "St7__cxx1112basic_stringIcSt11char_"
                  "traitsIcESaIcEE7compareEPK") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          bool isLlvmStdStringStdString =
              Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
              Callee->getName().find("_12basic_stringI") != std::string::npos &&
              Callee->getName().find("_11char_traits") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          bool isLlvmStdStringCString =
              Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
              Callee->getName().find("_12basic_stringI") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          /*
                    {

                       fprintf(stderr, "F:%s C:%s argc:%u\n",
                       F.getName().str().c_str(),
             Callee->getName().str().c_str(), FT->getNumParams());
                       fprintf(stderr, "ptr0:%u ptr1:%u ptr2:%u\n",
                              FT->getParamType(0)->isPointerTy(),
                              FT->getParamType(1)->isPointerTy(),
                              FT->getNumParams() > 2 ?
             FT->getParamType(2)->isPointerTy() : 22 );

                    }

          */

          if (isGccStdStringCString || isGccStdStringStdString ||
              isLlvmStdStringStdString || isLlvmStdStringCString) {
            isPtrRtn = false;
          }

          if (isPtrRtn) { calls.push_back(callInst); }
          if (isGccStdStringStdString) { gccStdStd.push_back(callInst); }
          if (isGccStdStringCString) { gccStdC.push_back(callInst); }
          if (isLlvmStdStringStdString) { llvmStdStd.push_back(callInst); }
          if (isLlvmStdStringCString) { llvmStdC.push_back(callInst); }
        }
      }
    }
  }

  if (!calls.size() && !gccStdStd.size() && !gccStdC.size() &&
      !llvmStdStd.size() && !llvmStdC.size()) {
    return false;
  }

  for (auto &callInst : calls) {
    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogHookFn, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";
  }

  for (auto &callInst : gccStdStd) {
    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogGccStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";
  }

  for (auto &callInst : gccStdC) {
    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogGccStdC, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";
  }

  for (auto &callInst : llvmStdStd) {
    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogLlvmStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";
  }

  for (auto &callInst : llvmStdC) {
    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogLlvmStdC, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";
  }

  return true;
}

#if USE_NEW_PM
PreservedAnalyses CmpLogRoutines::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool CmpLogRoutines::runOnModule(Module &M) {
#endif
  hookRtns(M);

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
static void registerCmpLogRoutinesPass(const PassManagerBuilder &,
                                       legacy::PassManagerBase &PM) {
  auto p = new CmpLogRoutines();
  PM.add(p);
}

static RegisterStandardPasses RegisterCmpLogRoutinesPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogRoutinesPass);

static RegisterStandardPasses RegisterCmpLogRoutinesPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogRoutinesPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmpLogRoutinesPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogRoutinesPass);
  #endif

#endif
