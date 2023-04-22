/*
   LibAFL - DumpCfg LLVM pass
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
#endif

#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#include <iostream>


using namespace llvm;

namespace {

#if USE_NEW_PM
class DumpCfgPass : public PassInfoMixin<DumpCfgPass> {
 public:
  DumpCfgPass() {
#else
class DumpCfgPass : public ModulePass {
 public:
  static char ID;

  DumpCfgPass() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
 private:
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DumpCfgPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(DumpCfgPass());
                });
          }};
}
#else
char DumpCfgPass::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses DumpCfgPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool DumpCfgPass::runOnModule(Module &M) {

#endif

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM

#else
static void registerDumpCfgPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new DumpCfgPass());
}

static RegisterPass<DumpCfgPass> X("dumpcfg",
                                      "dumpcfg instrumentation pass", false,
                                      false);

static RegisterStandardPasses RegisterDumpCfgPass(
    PassManagerBuilder::EP_OptimizerLast, registerDumpCfgPass);

static RegisterStandardPasses RegisterDumpCfgPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerDumpCfgPass);
#endif
