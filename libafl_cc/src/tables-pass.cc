/*
   LibAFL - Parsing tables coverage LLVM pass
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

#include <unordered_set>
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

using namespace llvm;

static cl::opt<bool> Debug("debug", cl::desc("Debug prints"), cl::init(false),
                           cl::NotHidden);

namespace {

Value *recurseCast(Value *V) {
  CastInst *CI;
  if ((CI = dyn_cast<CastInst>(V))) { return recurseCast(CI->getOperand(0)); }
  return V;
}

#ifdef USE_NEW_PM
class TamingParsingTables : public PassInfoMixin<TamingParsingTables> {
 public:
  TamingParsingTables() {
#else
class TamingParsingTables : public ModulePass {
 public:
  static char ID;
  TamingParsingTables() : ModulePass(ID) {
#endif
    // initInstrumentList();
  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t function_minimum_size = 1;
};

}  // namespace

#ifdef USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "TamingParsingTables", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(TamingParsingTables());
                });
  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {
              if (Name == "TamingParsingTables") {
                MPM.addPass(TamingParsingTables());
                return true;
              } else {
                return false;
              }
            });
  #endif
          }};
}
#else

char TamingParsingTables::ID = 0;
#endif

#ifdef USE_NEW_PM
PreservedAnalyses TamingParsingTables::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool TamingParsingTables::runOnModule(Module &M) {
#endif

  LLVMContext &C = M.getContext();

  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
  Type *VoidTy = Type::getVoidTy(C);

  FunctionCallee LogFunc = M.getOrInsertFunction("__libafl_tables_transition", VoidTy, Int32Ty, Int32Ty);

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif

  /* Instrument all the things! */

  for (auto &F : M) {
    int has_calls = 0;

    // if (!isInInstrumentList(&F)) { continue; }

    if (F.size() < function_minimum_size) { continue; }

    std::unordered_set<LoadInst *> loads;
    std::unordered_set<Value *>    geps;

    for (auto &BB : F) {
      for (auto &I : BB) {
        GetElementPtrInst *GEP;
        StoreInst         *ST;
        LoadInst          *LI;
        if ((LI = dyn_cast<LoadInst>(&I))) {
          loads.insert(LI);
        } else if ((GEP = dyn_cast<GetElementPtrInst>(&I))) {
          if (!GEP->hasIndices() || GEP->hasAllConstantIndices()) continue;
          // TODO handle multiple idxs
          Value *IDX = *GEP->idx_begin();
          IDX = recurseCast(IDX);
          
          if ((LI = dyn_cast<LoadInst>(IDX)) && loads.find(LI) != loads.end()) {
            geps.insert(GEP);
          }
        } else if ((ST = dyn_cast<StoreInst>(&I))) {
          Value    *PTR = ST->getPointerOperand();  // must be in a prev load
          Value    *VAL = recurseCast(ST->getValueOperand());
          LoadInst *GL = nullptr;
          Value    *V = nullptr;
          
          if ((GL = dyn_cast<LoadInst>(VAL))) {
            V = GL->getPointerOperand();
            if (V == nullptr || geps.find(V) == geps.end()) { continue; }
          } else {
            continue;
          }

          // the value comes from a load in which the ptr is obtained with a gep
          GEP = (GetElementPtrInst *)V;
          Value *IDX = *GEP->idx_begin();
          IDX = recurseCast(IDX);
          LI = dyn_cast<LoadInst>(IDX);

          if (LI == nullptr) continue;
          if (recurseCast(LI->getPointerOperand()) !=
              recurseCast(ST->getPointerOperand()))
            continue;

          std::string location = std::string("UNKNOWN");
          if (DILocation *Loc = GEP->getDebugLoc().get()) {
            location = std::string(Loc->getFilename().data()) +
                       std::string(":") + std::to_string(Loc->getLine());
          }

          errs() << "FOUND " << location << "\n\t" << *LI << "\n\t" << *GEP
                 << "\n\t" << *ST << "\n\n";
          
          IRBuilder<> IRB(ST);
          Value *A1 = IRB.CreateIntCast(LI, Int32Ty, false);
          Value *A2 = IRB.CreateIntCast(ST->getValueOperand(), Int32Ty, false);
          IRB.CreateCall(LogFunc, {A1, A2});
        }
      }
    }
  }

#ifdef USE_NEW_PM
  return PA;
#else
  return true;
#endif
}

#ifndef USE_NEW_PM
static void registerTablesPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new TamingParsingTables());
}

static RegisterStandardPasses RegisterTablesPass(
    PassManagerBuilder::EP_OptimizerLast, registerTablesPass);

static RegisterStandardPasses RegisterTablesPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerTablesPass);
#endif
