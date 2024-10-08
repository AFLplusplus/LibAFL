/*
   LibAFL - Ctx LLVM pass
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
class CtxPass : public PassInfoMixin<CtxPass> {
 public:
  CtxPass() {
#else
class CtxPass : public ModulePass {
 public:
  static char ID;

  CtxPass() : ModulePass(ID) {
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
  return {LLVM_PLUGIN_API_VERSION, "CtxPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(CtxPass());
                });
          }};
}
#else
char CtxPass::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses CtxPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool CtxPass::runOnModule(Module &M) {

#endif
  LLVMContext &C = M.getContext();
  auto         moduleName = M.getName();
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  uint32_t rand_seed;

  rand_seed = time(NULL);
  srand(rand_seed);

  GlobalVariable *AFLContext = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
  Value *PrevCtx =
      NULL;  // the ctx value up until now that we save on the stack

  for (auto &F : M) {
    int has_calls = 0;

    if (isIgnoreFunction(&F)) { continue; }
    if (F.size() < 1) { continue; }
    for (auto &BB : F) {
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      if (&BB == &F.getEntryBlock()) {
        // if this is the first block..
        LoadInst *PrevCtxLoad = IRB.CreateLoad(IRB.getInt32Ty(), AFLContext);
        PrevCtxLoad->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));
        PrevCtx = PrevCtxLoad;

        // now check for if calls exists
        for (auto &BB_2 : F) {
          if (has_calls) { break; }
          for (auto &IN : BB_2) {
            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {
              Function *Callee = callInst->getCalledFunction();
              if (!Callee || Callee->size() < 1) {
                continue;
              } else {
                has_calls = 1;
                break;
              }
            }
          }
        }

        if (has_calls) {
          Value *NewCtx = ConstantInt::get(Int32Ty, RandBelow(map_size));
          NewCtx = IRB.CreateXor(PrevCtx, NewCtx);
          StoreInst *StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
          StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));
        }
      }
      // Restore the ctx at the end of BB
      Instruction *Inst = BB.getTerminator();
      if (has_calls) {
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
          IRBuilder<> Post_IRB(Inst);
          StoreInst  *RestoreCtx;
          RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
        }
      }
    }
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
static void registerCtxPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new CtxPass());
}

static RegisterPass<CtxPass> X("ctx", "ctx instrumentation pass", false, false);

static RegisterStandardPasses RegisterCtxPass(
    PassManagerBuilder::EP_OptimizerLast, registerCtxPass);

static RegisterStandardPasses RegisterCtxPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCtxPass);
#endif
