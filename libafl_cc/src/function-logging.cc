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

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

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

class FunctionLogging : public PassInfoMixin<FunctionLogging> {
 public:
  FunctionLogging() {
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

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

PreservedAnalyses FunctionLogging::run(Module &M, ModuleAnalysisManager &MAM) {
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

  auto PA = PreservedAnalyses::all();
  return PA;
}