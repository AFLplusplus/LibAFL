/*
   LibAFL - Function Logging LLVM pass
   --------------------------------------------------

   Written by Dongjia Zhang <toka@aflplus.plus>

   Copyright 2022-2023 AFLplusplus Project. All rights reserved.

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
#else
  #include <io.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>
#include <set>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"

#if USE_NEW_PM
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#include <iostream>

using namespace llvm;

#define MAP_SIZE EDGES_MAP_DEFAULT_SIZE

namespace {

#if USE_NEW_PM
class FunctionLogging : public PassInfoMixin<FunctionLogging> {
 public:
  FunctionLogging() {
#else
class FunctionLogging : public ModulePass {
 public:
  static char ID;

  FunctionLogging() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t map_size = MAP_SIZE;

 private:
  bool isLLVMIntrinsicFn(StringRef &n) {
    // Not interested in these LLVM's functions
#if LLVM_VERSION_MAJOR >= 18
    if (n.starts_with("llvm.")) {
#else
    if (n.startswith("llvm.")) {
#endif
      return true;
    } else {
      return false;
    }
  }
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FunctionLoggingPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
  #if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
  #endif
                ) { MPM.addPass(FunctionLogging()); });
          }};
}
#else
char FunctionLogging::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses FunctionLogging::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool FunctionLogging::runOnModule(Module &M) {

#endif
  LLVMContext   &C = M.getContext();
  auto           moduleName = M.getName();
  Type          *VoidTy = Type::getVoidTy(C);
  IntegerType   *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType   *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType   *Int64Ty = IntegerType::getInt64Ty(C);
  FunctionCallee callHook;
  callHook =
      M.getOrInsertFunction("__libafl_target_call_hook", VoidTy, Int64Ty);
  uint32_t rand_seed;

  rand_seed = time(NULL);
  srand(rand_seed);

  for (auto &F : M) {
    int has_calls = 0;

    if (isIgnoreFunction(&F)) { continue; }
    if (F.size() < 1) { continue; }
    // instrument the first basic block of this fn
    BasicBlock &entry = F.front();
    std::size_t function_id = std::hash<std::string>{}(F.getName().str());
    IRBuilder<> IRB(&entry);
    IRB.SetInsertPoint(&entry.front());
    std::vector<Value *> args;
    llvm::Value         *value = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(F.getContext()), function_id);
    args.push_back(value);
    IRB.CreateCall(callHook, args);
  }

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM

#else
static void registerFunctionLoggingPass(const PassManagerBuilder &,
                                        legacy::PassManagerBase &PM) {
  PM.add(new FunctionLoggingPass());
}

static RegisterPass<FunctionLogging> X("function-logging",
                                       "function logging pass", false, false);

static RegisterStandardPasses RegisterFunctionLogging(
    PassManagerBuilder::EP_OptimizerLast, registerFunctionLoggingPass);

static RegisterStandardPasses RegisterFunctionLogging0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerFunctionLoggingPass);
#endif
